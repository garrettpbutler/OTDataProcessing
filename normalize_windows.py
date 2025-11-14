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

if __name__ == "__main__":
    print("Analyzing current window ranges...")
    analyze_window_ranges(INPUT_DIR)
    print()

    print("Processing CSV files...")
    normalize_window_numbers(INPUT_DIR, START_WINDOW_NUM, OUTPUT_DIR)