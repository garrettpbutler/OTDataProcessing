import pandas as pd
import os
import glob
from pathlib import Path

# Global variables
INPUT_DIR = "./csv"  # Directory containing CSV files
START_WINDOW_NUM = 4610  # New starting window number
OUTPUT_DIR = None  # Set to None to overwrite original files, or specify a different directory

def normalize_window_numbers(input_dir, start_window_num, output_dir=None):
    """
    Normalize window numbers across all CSV files to start from the specified number.
    
    Args:
        input_dir (str): Directory containing CSV files
        start_window_num (int): New starting window number
        output_dir (str): Output directory (None to overwrite original files)
    """
    
    if output_dir is None:
        output_dir = input_dir
    else:
        os.makedirs(output_dir, exist_ok=True)
    
    # Find all CSV files in the directory
    csv_files = glob.glob(os.path.join(input_dir, "*.csv"))
    
    if not csv_files:
        print(f"No CSV files found in {input_dir}")
        return
    
    print(f"Found {len(csv_files)} CSV files to process")
    print(f"Normalizing window numbers to start from {start_window_num}")
    
    for csv_file in csv_files:
        try:
            # Read the CSV file
            df = pd.read_csv(csv_file)
            
            # Check if Window_Num column exists
            if 'Window_Num' not in df.columns:
                print(f"Skipping {os.path.basename(csv_file)} - no Window_Num column")
                continue
            
            # Find the current starting window number
            current_start = df['Window_Num'].min()
            
            # Calculate the offset needed
            offset = current_start - start_window_num
            
            # Apply the offset to all window numbers
            df['Window_Num'] = df['Window_Num'] - offset
            
            # Determine output path
            if output_dir == input_dir:
                output_path = csv_file  # Overwrite original
            else:
                output_path = os.path.join(output_dir, os.path.basename(csv_file))
            
            # Save the modified CSV
            df.to_csv(output_path, index=False)
            
            print(f"Processed {os.path.basename(csv_file)}: {current_start} -> {start_window_num} (offset: {offset})")
            
        except Exception as e:
            print(f"Error processing {os.path.basename(csv_file)}: {e}")
    
    print(f"\nNormalization complete! All files now start from window {start_window_num}")

def normalize_window_numbers_files(csv_files, start_window_num, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    for csv_file in csv_files:
        df = pd.read_csv(csv_file)

        if 'Window_Num' not in df.columns or df.empty:
            continue

        current_start = df['Window_Num'].min()
        offset = current_start - start_window_num
        df['Window_Num'] = df['Window_Num'] - offset

        out_path = os.path.join(output_dir, os.path.basename(csv_file))
        df.to_csv(out_path, index=False)

def analyze_window_ranges(input_dir):
    """
    Analyze the window number ranges in all CSV files
    
    Args:
        input_dir (str): Directory containing CSV files
    """
    csv_files = glob.glob(os.path.join(input_dir, "*.csv"))
    
    if not csv_files:
        print(f"No CSV files found in {input_dir}")
        return
    
    print("Window number analysis:")
    
    for csv_file in csv_files:
        try:
            df = pd.read_csv(csv_file)
            if 'Window_Num' in df.columns:
                min_window = df['Window_Num'].min()
                max_window = df['Window_Num'].max()
                num_windows = len(df)
                print(f"{os.path.basename(csv_file):<40} | Windows: {min_window:>6} to {max_window:<6} | Count: {num_windows:>4}")
        except:
            print(f"{os.path.basename(csv_file):<40} | ERROR reading file")

def get_window_extremes(csv_file_path):
    """
    Inspect a single CSV file and return its window number extremes.

    Args:
        csv_file_path (str): Path to the CSV file

    Returns:
        dict: {
            'filename': str,
            'min': int | None,
            'max': int | None,
            'count': int
        }
    """
    filename = os.path.basename(csv_file_path)

    try:
        df = pd.read_csv(csv_file_path)

        if 'Window_Num' not in df.columns or df.empty:
            return {
                'filename': filename,
                'min': None,
                'max': None,
                'count': 0
            }

        return {
            'filename': filename,
            'min': int(df['Window_Num'].min()),
            'max': int(df['Window_Num'].max()),
            'count': int(len(df))
        }

    except Exception:
        return {
            'filename': filename,
            'min': None,
            'max': None,
            'count': 0
        }

def get_multiple_window_extremes(input_dir):
    """
    Inspect all CSV files in input_dir and return a dict with min/max window numbers per file.

    Returns:
        dict: mapping filename -> {'min': min_window_num, 'max': max_window_num, 'count': number_of_rows}
    """
    csv_files = glob.glob(os.path.join(input_dir, "*.csv"))
    extremes = {}
    for csv_file in csv_files:
        try:
            df = pd.read_csv(csv_file)
            if 'Window_Num' not in df.columns or df.empty:
                extremes[os.path.basename(csv_file)] = {'min': None, 'max': None, 'count': 0}
            else:
                extremes[os.path.basename(csv_file)] = {
                    'min': int(df['Window_Num'].min()),
                    'max': int(df['Window_Num'].max()),
                    'count': int(len(df))
                }
        except Exception as e:
            extremes[os.path.basename(csv_file)] = {'min': None, 'max': None, 'count': 0}
    return extremes

def trim_and_align(input_dir, output_dir=None, trim_start=None, trim_end=None):
    """
    Trim every CSV in input_dir to only include rows between trim_start and trim_end (inclusive).
    If output_dir is None, overwrite in-place; otherwise write to output_dir.

    Args:
        input_dir (str)
        output_dir (str|None)
        trim_start (int)
        trim_end (int)
    """
    if trim_start is None or trim_end is None:
        raise ValueError("trim_start and trim_end must be provided")

    if output_dir is None:
        output_dir = input_dir
    else:
        os.makedirs(output_dir, exist_ok=True)

    csv_files = glob.glob(os.path.join(input_dir, "*.csv"))
    for csv_file in csv_files:
        try:
            df = pd.read_csv(csv_file)
            if 'Window_Num' not in df.columns:
                # Nothing to trim; just copy if output_dir is different
                out_path = os.path.join(output_dir, os.path.basename(csv_file))
                if out_path != csv_file:
                    df.to_csv(out_path, index=False)
                continue

            # Filter rows that are within [trim_start, trim_end]
            trimmed_df = df[(df['Window_Num'] >= trim_start) & (df['Window_Num'] <= trim_end)]
            out_path = os.path.join(output_dir, os.path.basename(csv_file))
            trimmed_df.to_csv(out_path, index=False)
        except Exception as e:
            # Fail silently per-file but report
            print(f"Error trimming {os.path.basename(csv_file)}: {e}")

def trim_and_align_files(csv_files, output_dir, trim_start, trim_end):
    os.makedirs(output_dir, exist_ok=True)

    for csv_file in csv_files:
        df = pd.read_csv(csv_file)

        if 'Window_Num' not in df.columns:
            continue

        trimmed = df[
            (df['Window_Num'] >= trim_start) &
            (df['Window_Num'] <= trim_end)
        ]

        out_path = os.path.join(output_dir, os.path.basename(csv_file))
        trimmed.to_csv(out_path, index=False)

if __name__ == "__main__":
    print("Analyzing current window ranges...")
    analyze_window_ranges(INPUT_DIR)
    print()

    print("Processing CSV files...")
    normalize_window_numbers(INPUT_DIR, START_WINDOW_NUM, OUTPUT_DIR)