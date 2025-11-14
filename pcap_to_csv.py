import subprocess
import json
import csv
import os
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
import math
os.environ['PATH'] += r';C:\Program Files\Wireshark'

# Global variables
PCAP_FILE = "./pcap/GOOSE_Mirror.pcapng" # Path to input PCAP file
OUTPUT_DIR = "./csv"  # Directory to save output CSV files
bSaveJsonDebug = False # Set to True to save a full JSON output from tshark for debugging
bAddTime = False # Whether to add time offset to timestamps (used to fix RTAC time issues)
AddHours = 4 # Number of hours to add if adding time
AddMinutes = 40 # Number of minutes to add if adding time
AddSeconds = 35 # Number of seconds to add if adding time

# Global storage for time-window data
goose_time_windows = defaultdict(lambda: {
    'packet_count': 0,
    'total_length': 0,
    'eth_sources': set(),
    'eth_destinations': set(),
    'stream_flags': defaultdict(lambda: {  # Track per src/dst pair
        'last_stNum': None,
        'last_sqNum': None, 
        'last_confRev': None,
        'last_booleans': None,
        'stNum_changed': 0,
        'sqNum_reset': 0,
        'confRev_changed': 0,
        'boolean_changed': 0
    })
})

goose_stream_states = {}

# Global variables to track data object state across windows
communication_pairs = {}

port_states = {}
dnp3_data_states = {}

def get_pair_key(packet, protocol):
    """
    Create a unique key for each src/dst pair based on protocol
    
    Args:
        packet (dict): Parsed packet data
        protocol (str): Protocol type ('dnp3', 'goose', 'sv', 'tcp')
        
    Returns:
        str: Unique key for the communication pair
    """
    if protocol in ['dnp3', 'tcp']:
        # For IP-based protocols, use IP addresses (ignore ports)
        ip_layer = packet['_source']['layers'].get('ip', {})
        source_ip = ip_layer.get('ip.src', 'unknown')
        dest_ip = ip_layer.get('ip.dst', 'unknown')
        
        tcp_layer = packet['_source']['layers'].get('tcp', {})
        source_port = tcp_layer.get('tcp.srcport', '')
        dest_port = tcp_layer.get('tcp.dstport', '')
        
        # Handle localhost special cases - preserves directionality
        if source_ip == '127.0.0.1':
            # Determine which IP this localhost represents based on port
            if source_port == '20000':
                source_ip = '192.168.1.80'  # Outstation
            else:
                source_ip = '192.168.1.70'  # Master
                
        if dest_ip == '127.0.0.1':
            # Determine which IP this localhost represents based on port  
            if dest_port == '20000':
                dest_ip = '192.168.1.80'  # Outstation
            else:
                dest_ip = '192.168.1.70'  # Master
            
        pair_key = f"{protocol}_{source_ip}_{dest_ip}"
        return pair_key
    
    elif protocol in ['goose', 'sv']:
        # For Ethernet-based protocols, use MAC addresses
        eth_layer = packet['_source']['layers'].get('eth', {})
        source_mac = eth_layer.get('eth.src', 'unknown')
        dest_mac = eth_layer.get('eth.dst', 'unknown')
        return f"{protocol}_{source_mac}_{dest_mac}"
    
    else:
        # Fallback for other protocols
        return f"{protocol}_unknown_unknown"

def parse_wireshark_timestamp(timestamp_str):
    """
    Takes in a Wireshark timestamp string and returns a datetime object.
    
    Args:
        timestamp_str (str): Wireshark timestamp string
    
    Returns:
        datetime: Parsed datetime object
    """
    # Remove timezone
    if 'Eastern Daylight Time' in timestamp_str:
        clean = timestamp_str.split(' Eastern Daylight Time')[0].strip()
    elif 'Eastern Standard Time' in timestamp_str:
        clean = timestamp_str.split(' Eastern Standard Time')[0].strip()
    
    # Split by spaces
    parts = clean.split()
    
    if len(parts) == 4:
        month_str, day_str, year_str, time_str = parts
        
        # Remove comma from day
        day_str = day_str.rstrip(',')
        
        # Month mapping
        month_map = {
            'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
            'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
        }
        
        month = month_map[month_str]
        day = int(day_str)
        year = int(year_str)
        
        # Parse time HH:MM:SS.microseconds
        time_parts = time_str.split(':')
        hour = int(time_parts[0])
        minute = int(time_parts[1])
        
        # Handle seconds and microseconds
        sec_usec = time_parts[2].split('.')
        second = int(sec_usec[0])
        microsecond = int(sec_usec[1][:6])  # Trim to 6 digits max
        
        return datetime(year, month, day, hour, minute, second, microsecond)
    else:
        print(f"{clean}")
        for part in parts:
            print(f"Parts: {part}")
    
    raise ValueError(f"Unexpected format: {clean}")

def get_window_number(timestamp):
    """
    Convert timestamp to 5-second window number.
    
    Args:
        timestamp (str): Wireshark timestamp string
    
    Returns:
        int: Corresponding 5-second window number
    """    
    # Parse timestamp using the robust parser
    dt = parse_wireshark_timestamp(timestamp)

    if bAddTime:
        time_delta = timedelta(hours=AddHours, minutes=AddMinutes, seconds=AddSeconds)
        dt = dt + time_delta
    
    # Calculate seconds since midnight for easier math
    seconds_since_midnight = dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1000000
    
    # Find which 5-second window this belongs to (starting with window 1)
    window_num = math.floor(seconds_since_midnight / 5) + 1
    
    return window_num

def reset_window_data():
    """Clear all window data (call when starting new file)"""
    global communication_pairs, goose_stream_states, port_states, dnp3_data_states
    
    communication_pairs = {}
    goose_stream_states = {}
    port_states = {}
    dnp3_data_states = {}

def pcap_to_json(pcap_file):
    """
    Convert PCAP to JSON while preserving all DNP3 objects
    
    Args:
        pcap_file (str): Path to the PCAP file
        
    Returns:
        list: Parsed JSON data from tshark
    """
    # Ensure pcap_file exists
    if not os.path.exists(pcap_file):
        print(f"ERROR: PCAP file not found: {pcap_file}")
        raise RuntimeError("Please check file path and try again")
    
    tshark_paths = [
        'tshark',
        r'C:\Program Files\Wireshark\tshark.exe',
        r'C:\Program Files (x86)\Wireshark\tshark.exe'
    ]

    for path in tshark_paths:
        try:
            # Try JSON with verbose DNP3 dissection
            cmd = [
                path,
                '-r', pcap_file,
                '-T', 'json',
                '-d', 'udp.port==20000,dnp3',  # Force DNP3 dissection
                '-V'  # Verbose (shows all tree items)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Custom JSON parsing that preserves repeated keys
            def parse_object_pairs(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        if isinstance(result[key], list):
                            result[key].append(value)
                        else:
                            result[key] = [result[key], value]
                    else:
                        result[key] = value
                return result

            parsed_data = json.loads(result.stdout, object_pairs_hook=parse_object_pairs)

            # Save debug JSON file
            if bSaveJsonDebug:
                debug_filename = os.path.join(
                    OUTPUT_DIR,
                    f"debug_{os.path.basename(pcap_file)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                )
                with open(debug_filename, 'w') as f:
                    json.dump(parsed_data, f, indent=2)
                
                print(f"Debug JSON saved to: {debug_filename}")
            
            return parsed_data

        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            continue

    raise RuntimeError("Tshark not found in standard locations")

def get_protocol_type(packet):
    """
    Determine protocol type from frame.protocols field
    
    Args:
        packet (dict): Parsed packet data
        
    Returns:
        str: Protocol type ('dnp3', 'goose', 'tcp', or None)
    """
    protocols = packet['_source']['layers']['frame']['frame.protocols']
    protocol_list = protocols.split(':')

    # Check for target protocols, add more as needed
    # Some protocols (like DNP3) may be encapsulated in TCP so check for those first
    for proto in ['dnp3', 'goose']:
        if proto in protocol_list:
            return proto
        elif 'tcp' in protocol_list:
            return 'tcp'

    return None

def initialize_pair_data(protocol):
    """
    Initialize data structure for a new communication pair
    
    Args:
        protocol (str): Protocol type ('dnp3', 'goose', 'tcp')
        
    Returns:
        defaultdict: Initialized data structure for the pair
    """
    if protocol == 'tcp':
        return defaultdict(lambda: {
            'packet_count': 0,
            'total_length': 0,
            'streams': set(),
            'flag_ack': 0,
            'flag_retransmission': 0, 
            'flag_reset': 0,
            'flag_syn': 0,
            'flag_fin': 0,
            'src_port_changed': 0,
            'dst_port_changed': 0,
            'rtt': 0
        })
    elif protocol == 'dnp3':
        return defaultdict(lambda: {
            'packet_count': 0,
            'total_dnp3_length': 0,
            'function_codes': defaultdict(int),
            'iin_val_change': 0,
            'binary_inputs': None,
            'analog_inputs': None,
            'data_object_changed': 0,
            'analog_input_changed': 0,
            'binary_input_changed': 0,
            'src_port_changed': 0,
            'dst_port_changed': 0
        })
    elif protocol == 'goose':
        return defaultdict(lambda: {
            'packet_count': 0,
            'total_length': 0,
            'stream_flags': {
                'stNum_changed': 0,
                'sqNum_reset': 0,
                'confRev_changed': 0,
                'boolean_changed': 0,
                'num_events': 0
            }
        })
    else:
        return defaultdict(lambda: {'packet_count': 0, 'total_length': 0})

def initialize_port_states(pair_key):
    """
    Initialize port tracking for a new communication pair
    
    Args:
        pair_key (str): Unique key for the target communication pair    
    """
    port_states[pair_key] = {
        'last_src_port': None,
        'last_dst_port': None,
        'window_changes': {}  # Track changes per window
    }

def initialize_goose_states(pair_key):
    """
    Initialize GOOSE state tracking for a new communication pair
    
    Args:
        pair_key (str): Unique key for the target communication pair    
    """
    goose_stream_states[pair_key] = {
        'last_stNum': None,
        'last_sqNum': None,
        'last_confRev': None,
        'last_booleans': None
    }

def update_goose_states(pair_key, stNum, sqNum, confRev, booleans):
    """
    Update GOOSE states and track changes across window boundaries
    
    Args:
        pair_key (str): Unique key for the target communication pair
        stNum (int): Current stNum value
        sqNum (int): Current sqNum value  
        confRev (int): Current confRev value
        booleans (list): Current boolean data list
        
    Returns:
        dict: Change flags for this window
    """
    if pair_key not in goose_stream_states:
        initialize_goose_states(pair_key)
    
    goose_state = goose_stream_states[pair_key]
    
    # Initialize change flags
    changes = {
        'stNum_changed': 0,
        'sqNum_reset': 0,
        'confRev_changed': 0,
        'boolean_changed': 0
    }
    
    # For the very first packet in this pair, initialize states but don't count as change
    if goose_state['last_stNum'] is None:
        goose_state['last_stNum'] = stNum
        goose_state['last_sqNum'] = sqNum
        goose_state['last_confRev'] = confRev
        goose_state['last_booleans'] = booleans
        return changes
    
    # Check stNum change
    if stNum != goose_state['last_stNum']:
        changes['stNum_changed'] = 1
    
    # Check sqNum reset/sequence break
    if goose_state['last_sqNum'] is not None and sqNum is not None:
        try:
            current_sqNum = int(sqNum)
            last_sqNum = int(goose_state['last_sqNum'])
            # Check if sequence doesn't increase by exactly 1
            if current_sqNum != last_sqNum + 1:
                changes['sqNum_reset'] = 1
        except (ValueError, TypeError):
            pass
    
    # Check confRev change
    if confRev != goose_state['last_confRev']:
        changes['confRev_changed'] = 1
    
    # Check boolean data change
    if booleans and goose_state['last_booleans'] is not None:
        if booleans != goose_state['last_booleans']:
            changes['boolean_changed'] = 1
    
    # Update state for next packet comparison
    goose_state['last_stNum'] = stNum
    goose_state['last_sqNum'] = sqNum  
    goose_state['last_confRev'] = confRev
    goose_state['last_booleans'] = booleans
    
    return changes

def update_port_states(pair_key, src_port, dst_port, window_num):
    """
    Update port states and track changes across window boundaries
    
    Args:
        pair_key (str): Unique key for the target communication pair
        src_port (str): Current source port
        dst_port (str): Current destination port
        window_num (int): Current window number
        
    Returns:
        dict: Change flags for source and destination ports in this window
    """
    if pair_key not in port_states:
        initialize_port_states(pair_key)
    
    port_state = port_states[pair_key]
    
    # Initialize window change tracking
    if window_num not in port_state['window_changes']:
        port_state['window_changes'][window_num] = {
            'src_changed': 0,
            'dst_changed': 0
        }
    
    # For the very first packet in this pair, initialize ports but don't count as change
    if port_state['last_src_port'] is None:
        # First time seeing this pair, initialize ports but no change
        port_state['last_src_port'] = src_port
        port_state['last_dst_port'] = dst_port
        return port_state['window_changes'][window_num]
    
    # Check source port change (only if we have previous values)
    if src_port != port_state['last_src_port'] and src_port != port_state['last_dst_port']:
        port_state['window_changes'][window_num]['src_changed'] = 1
        port_state['last_src_port'] = src_port
    
    # Check destination port change (only if we have previous values)
    if dst_port != port_state['last_dst_port'] and dst_port != port_state['last_src_port']:
        port_state['window_changes'][window_num]['dst_changed'] = 1
        port_state['last_dst_port'] = dst_port
    
    return port_state['window_changes'][window_num]

def process_dnp3(packet):
    """
    Process DNP3 packets by communication pair
    
    Args:
        packet (dict): Parsed packet data
    """
    try:
        # Extract basic packet info
        frame = packet['_source']['layers']['frame']
        ip_layer = packet['_source']['layers'].get('ip', {})
        tcp_layer = packet['_source']['layers'].get('tcp', {})

        source_ip = ip_layer.get('ip.src')
        dest_ip = ip_layer.get('ip.dst')
        source_port = tcp_layer.get('tcp.srcport')
        dest_port = tcp_layer.get('tcp.dstport')

        # Handle 127.0.0.1 special cases
        if source_ip == '127.0.0.1':
            source_ip = '192.168.1.80' if source_port == '20000' else '192.168.1.70'
        if dest_ip == '127.0.0.1':
            dest_ip = '192.168.1.80' if dest_port == '20000' else '192.168.1.70'

        # Find DNP3 layers
        dnp3 = packet['_source']['layers']['dnp3']
        link_layer_key = next((k for k in dnp3.keys() if k.startswith("Data Link Layer")), None)
        if not link_layer_key:
            return None, None

        link_layer = dnp3[link_layer_key]
        link_control = link_layer['dnp3.ctl_tree']

        transport_layer = dnp3['dnp3.tr.ctl_tree']

        app_layer_key = next((k for k in dnp3.keys() if k.startswith("Application Layer")), None)
        if not app_layer_key:
            return None, None

        app_layer = dnp3[app_layer_key]
    except KeyError:
        return None, None
    
    # Get timestamp and window number
    timestamp = frame.get('frame.time')
    try:
        window_num = get_window_number(timestamp)
    except Exception as e:
        print(f"Error parsing DNP3 timestamp '{timestamp}': {e}")
        return None, None
    
    # Get communication pair key
    pair_key = get_pair_key(packet, 'dnp3')
    
    # Initialize if this is a new pair
    if pair_key not in communication_pairs:
        communication_pairs[pair_key] = initialize_pair_data('dnp3')
    
    # Extract DNP3 features
    try:
        dnp3_length = int(link_layer.get('dnp3.len'))
        function_code = int(app_layer.get('dnp3.al.func', '0'))
    except:
        return pair_key, window_num
    
    # Extract IIN Bits - only track if any IIN bits were set
    iin_bits_set = False
    
    if 'dnp3.al.iin_tree' in app_layer:
        iin_bits = app_layer['dnp3.al.iin_tree']
        iin_fields = [
            'dnp3.al.iin.rst', 'dnp3.al.iin.dt', 'dnp3.al.iin.dol', 'dnp3.al.iin.tsr',
            'dnp3.al.iin.cls3d', 'dnp3.al.iin.cls2d', 'dnp3.al.iin.cls1d', 'dnp3.al.iin.bmsg',
            'dnp3.al.iin.cc', 'dnp3.al.iin.oae', 'dnp3.al.iin.ebo', 'dnp3.al.iin.pioor',
            'dnp3.al.iin.obju', 'dnp3.al.iin.fcni'
        ]

        for field in iin_fields:
            if iin_bits.get(field) == '1':
                iin_bits_set = True
                break 

    analog_change_found = False
    binary_change_found = False

    if 'RESPONSE Data Objects' in app_layer:
        response_objects = app_layer['RESPONSE Data Objects']
        application_objects = response_objects.get('dnp3.al.obj', {})
        if "0x2002" in application_objects:
            analog_change_found = True
            print(f"DEBUG: Analog input change detected in application objects.")
        if "0x0202" in application_objects:
            binary_change_found = True
            print(f"DEBUG: Binary input change detected in application objects.")

    # Update window data for this specific pair
    pair_data = communication_pairs[pair_key]
    window_data = pair_data[window_num]
    
    window_data['packet_count'] += 1
    window_data['total_dnp3_length'] += dnp3_length
    
    # Count function codes
    if function_code in [0, 1, 2, 4, 5, 6, 13, 14, 129, 130]:
        window_data['function_codes'][function_code] += 1
    
    # Track IIN bits
    if iin_bits_set:
        window_data['iin_val_change'] = 1

    if analog_change_found:
        window_data['analog_input_changed'] = 1
    if binary_change_found:
        window_data['binary_input_changed'] = 1

    # Track port changes (returns the change flags for this window)
    port_changes = update_port_states(pair_key, source_port, dest_port, window_num)
    window_data['src_port_changed'] = port_changes['src_changed']
    window_data['dst_port_changed'] = port_changes['dst_changed']

    return pair_key, window_num

def process_goose(packet):
    """
    Process GOOSE packets by communication pair
    
    Args:
        packet (dict): Parsed packet data
    """
    try:
        # Extract basic packet info
        frame = packet['_source']['layers']['frame']
        eth = packet['_source']['layers']['eth']
        goose = packet['_source']['layers']['goose']
        goose_pdu = goose['goose.goosePdu_element']
    except KeyError:
        return None, None

    # Get timestamp and window number
    timestamp = frame.get('frame.time')
    try:
        window_num = get_window_number(timestamp)
    except Exception as e:
        print(f"Error parsing GOOSE timestamp '{timestamp}': {e}")
        return None, None

    # Get communication pair key
    pair_key = get_pair_key(packet, 'goose')
    
    # Initialize if this is a new pair
    if pair_key not in communication_pairs:
        communication_pairs[pair_key] = initialize_pair_data('goose')

    # Extract GOOSE features
    eth_src = eth.get('eth.src', '')
    eth_dst = eth.get('eth.dst', '')
    length = int(frame.get('frame.len', 0))
    
    # Extract GOOSE fields
    stNum = goose_pdu.get('goose.stNum')
    sqNum = goose_pdu.get('goose.sqNum')
    confRev = goose_pdu.get('goose.confRev')
    
    # Extract ALL boolean data (not just the last one)
    current_booleans = extract_goose_booleans(goose_pdu)

    # Update window data for this specific pair
    pair_data = communication_pairs[pair_key]
    window_data = pair_data[window_num]
    
    window_data['packet_count'] += 1
    window_data['total_length'] += length
    
    # Get change flags
    changes = update_goose_states(pair_key, stNum, sqNum, confRev, current_booleans)
    
    # Update window data with change flags
    if changes['stNum_changed'] == 1:
        window_data['stream_flags']['stNum_changed'] = 1
    if changes['sqNum_reset'] == 1:
        window_data['stream_flags']['sqNum_reset'] = 1
    if changes['confRev_changed'] == 1:
        window_data['stream_flags']['confRev_changed'] = 1
    if changes['boolean_changed'] == 1:
        window_data['stream_flags']['boolean_changed'] = 1
    
    # Count events (any change constitutes an event)
    if any(changes.values()):
        window_data['stream_flags']['num_events'] += 1

    return pair_key, window_num

def extract_goose_booleans(goose_pdu):
    """
    Extract only the actual GOOSE data boolean values without nested metadata
    
    Args:
        goose_pdu (dict): Parsed GOOSE PDU data
        
    Returns:
        list: List of boolean values extracted from the GOOSE data"""
    booleans = []
    
    def extract_from_datatree(data_tree):
        """Recursively extract boolean values from goose.Data_tree structures"""
        if not isinstance(data_tree, (dict, list)):
            return
            
        if isinstance(data_tree, list):
            for item in data_tree:
                extract_from_datatree(item)
        elif isinstance(data_tree, dict):
            # Look for direct goose.boolean entries
            if 'goose.boolean' in data_tree:
                try:
                    bool_val = bool(int(data_tree['goose.boolean']))
                    booleans.append(bool_val)
                except (ValueError, TypeError):
                    pass
            
            # Also check if this is a simple data entry (not a structure) that contains a boolean value
            data_type = data_tree.get('goose.Data') if 'goose.Data' in data_tree else None
            if data_type == '3' and 'goose.boolean' in data_tree:
                try:
                    bool_val = bool(int(data_tree['goose.boolean']))
                    booleans.append(bool_val)
                except (ValueError, TypeError):
                    pass
            
            # Recursively check other keys
            for key, value in data_tree.items():
                if key not in ['goose.Data', 'goose.Data_tree']:  # Avoid re-processing the main arrays
                    extract_from_datatree(value)
    
    # Start extraction from the allData_tree
    if 'goose.allData_tree' in goose_pdu:
        all_data_tree = goose_pdu['goose.allData_tree']
        
        # First, handle the top-level Data_tree array
        if 'goose.Data_tree' in all_data_tree:
            data_tree = all_data_tree['goose.Data_tree']
            
            # Process each item in the Data_tree
            if isinstance(data_tree, list):
                for item in data_tree:
                    # This is where the actual GOOSE data values are
                    if isinstance(item, dict):
                        # Direct boolean entry
                        if 'goose.boolean' in item:
                            try:
                                bool_val = bool(int(item['goose.boolean']))
                                booleans.append(bool_val)
                            except (ValueError, TypeError):
                                pass
                        
                        # Structured data containing booleans
                        elif 'goose.structure_tree' in item:
                            structure_tree = item['goose.structure_tree']
                            if 'goose.Data_tree' in structure_tree:
                                # Extract from the nested structure
                                extract_from_datatree(structure_tree['goose.Data_tree'])
    
    return booleans

def process_tcp(packet):
    """
    Process TCP packets by communication pair
    
    Args:
        packet (dict): Parsed packet data
    """
    try:
        # Extract basic packet info
        frame = packet['_source']['layers']['frame']
        ip_layer = packet['_source']['layers'].get('ip', {})
        tcp_layer = packet['_source']['layers']['tcp']
    except KeyError:
        return None, None

    timestamp = frame.get('frame.time')
    try:
        window_num = get_window_number(timestamp)
    except Exception as e:
        print(f"Error parsing timestamp '{timestamp}': {e}")
        return None, None
    
    # Get communication pair key
    pair_key = get_pair_key(packet, 'tcp')
    
    # Initialize if this is a new pair
    if pair_key not in communication_pairs:
        communication_pairs[pair_key] = initialize_pair_data('tcp')
    
    # Extract features
    source_ip = ip_layer.get('ip.src', '')
    dest_ip = ip_layer.get('ip.dst', '')
    source_port = tcp_layer.get('tcp.srcport', '')
    dest_port = tcp_layer.get('tcp.dstport', '')
    stream = tcp_layer.get('tcp.stream', '')
    length = int(frame.get('frame.len', 0))
    flags = tcp_layer.get('tcp.flags', '0x000')

    # Update window data for this specific pair
    pair_data = communication_pairs[pair_key]
    window_data = pair_data[window_num]
    
    window_data['packet_count'] += 1
    window_data['total_length'] += length

    if stream:
        window_data['streams'].add(stream)

    # Parse and track specific TCP flags
    try:
        flags_int = int(flags, 16) if flags.startswith('0x') else int(flags)
        
        # Check each flag we care about and set if present
        if flags_int & 0x010:  # Acknowledgement
            window_data['flag_ack'] = 1
        if flags_int & 0x008:  # Push (Retransmission)
            window_data['flag_retransmission'] = 1
        if flags_int & 0x004:  # Reset
            window_data['flag_reset'] = 1
        if flags_int & 0x002:  # Syn
            window_data['flag_syn'] = 1
        if flags_int & 0x001:  # Fin
            window_data['flag_fin'] = 1
            
    except:
        pass

    analysis = tcp_layer.get('tcp.analysis', {})
    # Calculate Round Trip Time (RTT) if available
    if 'tcp.analysis.ack_rtt' in analysis:
        try:
            rtt_str = analysis['tcp.analysis.ack_rtt']
            rtt_value = float(rtt_str)
            window_data['rtt'] = rtt_value
        except:
            pass

    # Track port changes
    port_changes = update_port_states(pair_key, source_port, dest_port, window_num)
    window_data['src_port_changed'] = port_changes['src_changed']
    window_data['dst_port_changed'] = port_changes['dst_changed']

    return pair_key, window_num

def write_communication_pairs_to_csv(output_dir):
    """
    Write each communication pair to its own CSV file
    
    Args:
        output_dir (str): Directory to save output CSV files"""
    pcap_stem = Path(PCAP_FILE).stem
    
    for pair_key, pair_data in communication_pairs.items():
        # Parse pair key to determine protocol and filename
        parts = pair_key.split('_')
        protocol = parts[0]
        src = parts[1]
        dst = parts[2]
        
        # Sanitize MAC addresses by replacing colons with dashes or removing them
        src_sanitized = src.replace(':', '-')
        dst_sanitized = dst.replace(':', '-')
        
        # Create descriptive filename with sanitized MAC addresses
        filename = f"{pcap_stem}_{protocol}_{src_sanitized}_to_{dst_sanitized}.csv"
        output_file = Path(output_dir) / filename
        
        print(f"Writing {protocol} pair to: {filename}")
        
        if protocol == 'tcp':
            write_tcp_pair_to_csv(pair_key, pair_data, output_file)
        elif protocol == 'dnp3':
            write_dnp3_pair_to_csv(pair_key, pair_data, output_file)
        elif protocol == 'goose':
            write_goose_pair_to_csv(pair_key, pair_data, output_file)

def write_tcp_pair_to_csv(pair_key, pair_data, output_file):
    """
    Write TCP communication pair data to CSV with individual flag features
    
    Args:
        pair_key (str): Unique key for the communication pair
        pair_data (dict): Data for the communication pair
        output_file (str): Path to output CSV file
    """
    csv_data = []
    for window_num, window_data in sorted(pair_data.items()):
        if window_data['packet_count'] > 0:
            avg_length = window_data['total_length'] / window_data['packet_count']
            
            row = {
                "Window_Num": window_num,
                "Num_Packets": window_data['packet_count'],
                "Avg_Length": round(avg_length, 2),
                "Flag_Ack": window_data.get('flag_ack', 0),
                "Flag_Retransmission": window_data.get('flag_retransmission', 0),
                "Flag_Reset": window_data.get('flag_reset', 0),
                "Flag_Syn": window_data.get('flag_syn', 0),
                "Flag_Fin": window_data.get('flag_fin', 0),
                "Src_Port_Changed": window_data.get('src_port_changed', 0),
                "Dst_Port_Changed": window_data.get('dst_port_changed', 0),
                "Round_Trip_Time": window_data.get('rtt', 0)
            }
            csv_data.append(row)
    
    if csv_data:
        fieldnames = [
            'Window_Num', 'Num_Packets', 'Avg_Length','Flag_Ack', 
            'Flag_Retransmission', 'Flag_Reset', 'Flag_Syn', 'Flag_Fin',
            'Src_Port_Changed', 'Dst_Port_Changed', 'Round_Trip_Time'
        ]
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in csv_data:
                writer.writerow(row)
        print(f"TCP pair {pair_key} written to: {output_file}")

def write_dnp3_pair_to_csv(pair_key, pair_data, output_file):
    """
    Write DNP3 communication pair data to CSV with individual function code features
    
    Args:
        pair_key (str): Unique key for the communication pair
        pair_data (dict): Data for the communication pair
        output_file (str): Path to output CSV file
    """
    csv_data = []
    for window_num, window_data in sorted(pair_data.items()):
        if window_data['packet_count'] > 0:
            avg_dnp3_length = window_data['total_dnp3_length'] / window_data['packet_count']
            
            # Extract individual function code counts
            func_codes = window_data['function_codes']
            
            # FIX: Explicitly get port change values, default to 0 if not present
            src_port_changed = window_data.get('src_port_changed', 0)
            dst_port_changed = window_data.get('dst_port_changed', 0)
            
            row = {
                "Window_Num": window_num,
                "Num_Packets": window_data['packet_count'],
                "Avg_DNP3_Length": round(avg_dnp3_length, 2),
                "F0_Confirm": func_codes.get(0, 0),
                "F1_Read": func_codes.get(1, 0),
                "F2_Write": func_codes.get(2, 0),
                "F4_Operate": func_codes.get(4, 0),
                "F5_DirectOperate": func_codes.get(5, 0),
                "F6_DirectOperate_NoResp": func_codes.get(6, 0),
                "F13_ColdRestart": func_codes.get(13, 0),
                "F14_WarmRestart": func_codes.get(14, 0),
                "F129_Response": func_codes.get(129, 0),
                "F130_UnsolicitedResponse": func_codes.get(130, 0),
                "IIN_Val_Change": window_data.get('iin_val_change', 0),
                "Analog_Input_Change": window_data.get('analog_input_changed', 0),
                "Binary_Input_Change": window_data.get('binary_input_changed', 0),
                "Src_Port_Changed": src_port_changed,
                "Dst_Port_Changed": dst_port_changed
            }
            csv_data.append(row)
    
    if csv_data:
        fieldnames = [
            'Window_Num', 'Num_Packets', 'Avg_DNP3_Length',
            'F0_Confirm', 'F1_Read', 'F2_Write', 'F4_Operate', 'F5_DirectOperate',
            'F6_DirectOperate_NoResp', 'F13_ColdRestart', 'F14_WarmRestart',
            'F129_Response', 'F130_UnsolicitedResponse', 'IIN_Val_Change', 
            'Analog_Input_Change', 'Binary_Input_Change', 'Src_Port_Changed', 
            'Dst_Port_Changed'
        ]
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in csv_data:
                writer.writerow(row)
        print(f"DNP3 pair {pair_key} written to: {output_file}")

def write_goose_pair_to_csv(pair_key, pair_data, output_file):
    """
    Write GOOSE communication pair data to CSV
    
    Args:
        pair_key (str): Unique key for the communication pair
        pair_data (dict): Data for the communication pair
        output_file (str): Path to output CSV file"""
    csv_data = []
    for window_num, window_data in sorted(pair_data.items()):
        if window_data['packet_count'] > 0:
            avg_length = window_data['total_length'] / window_data['packet_count']
            
            # Extract stream flags directly
            stream_flags = window_data['stream_flags']
            
            row = {
                "Window_Num": window_num,
                "Num_Packets": window_data['packet_count'],
                "Avg_Length": round(avg_length, 2),
                "stNum_Change": stream_flags['stNum_changed'],
                "sqNum_Reset": stream_flags['sqNum_reset'],
                "ConfRev_Change": stream_flags['confRev_changed'],
                "Boolean_Data_Change": stream_flags['boolean_changed'],
                "Num_Events": stream_flags['num_events']
            }
            csv_data.append(row)
    
    if csv_data:
        fieldnames = [
            'Window_Num', 'Num_Packets', 'Avg_Length', 
            'stNum_Change', 'sqNum_Reset', 'ConfRev_Change', 
            'Boolean_Data_Change', 'Num_Events'
        ]
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in csv_data:
                writer.writerow(row)
        print(f"GOOSE pair {pair_key} written to: {output_file}")

def process_pcap(pcap_file, output_dir='output'):
    """
    Main processing function with communication pair separation
    
    Args:
        pcap_file (str): Path to the input PCAP file
        output_dir (str): Directory to save output CSV files"""
    global communication_pairs, goose_stream_states
    communication_pairs = {}
    goose_stream_states = {}

    reset_window_data()
    
    os.makedirs(output_dir, exist_ok=True)

    try:
        packets = pcap_to_json(pcap_file)
        if not packets:
            print("Warning: No packets found in PCAP file")
            return
    except Exception as e:
        print(f"Error converting PCAP to JSON: {str(e)}")
        return
    
    # Process each packet
    processed_pairs = set()
    for packet in packets:
        try:
            protocol = get_protocol_type(packet)
            if not protocol:
                continue

            # Process based on protocol type
            pair_key = None
            if protocol == 'tcp':
                pair_key, _ = process_tcp(packet)
            elif protocol == 'dnp3':
                pair_key, _ = process_dnp3(packet)
            elif protocol == 'goose':
                pair_key, _ = process_goose(packet)
            
            if pair_key and pair_key not in processed_pairs:
                processed_pairs.add(pair_key)
                print(f"Found new communication pair: {pair_key}")

        except Exception as e:
            print(f"Error processing packet: {str(e)}")
            continue

    # Write all communication pairs to separate CSV files
    write_communication_pairs_to_csv(output_dir)
    print(f"Processing complete. Found {len(communication_pairs)} unique communication pairs")

if __name__ == "__main__":
    process_pcap(PCAP_FILE, OUTPUT_DIR)
    print(f"Processing complete. CSV files saved to {OUTPUT_DIR}/")