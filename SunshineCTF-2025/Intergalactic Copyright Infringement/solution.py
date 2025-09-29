#!/usr/bin/env python3
import subprocess
import binascii
import sys

def extract_pieces():
    """Extract all BitTorrent pieces with their metadata"""
    cmd = [
        'tshark', '-r', 'evidence.pcapng',
        '-Y', 'bittorrent.msg.type == 7',
        '-T', 'fields',
        '-e', 'bittorrent.piece.index',
        '-e', 'bittorrent.piece.begin', 
        '-e', 'bittorrent.piece.data'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running tshark: {result.stderr}")
        return {}
    
    pieces = {}
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
            
        parts = line.split('\t')
        if len(parts) >= 3:
            piece_idx = int(parts[0], 16)
            begin_offset = int(parts[1], 16) 
            piece_data = parts[2]
            
            if piece_idx not in pieces:
                pieces[piece_idx] = {}
            
            pieces[piece_idx][begin_offset] = piece_data
    
    return pieces

def reassemble_file(pieces):
    """Reassemble pieces into complete file"""
    complete_data = b""
    
    # Sort pieces by index
    for piece_idx in sorted(pieces.keys()):
        print(f"Processing piece {piece_idx:02x}")
        piece_data = b""
        
        # Sort offsets within each piece
        for offset in sorted(pieces[piece_idx].keys()):
            hex_data = pieces[piece_idx][offset]
            if hex_data:  # Skip empty data
                try:
                    chunk = binascii.unhexlify(hex_data)
                    piece_data += chunk
                    print(f"  Offset {offset:06x}: {len(chunk)} bytes")
                except Exception as e:
                    print(f"  Error decoding offset {offset:06x}: {e}")
        
        complete_data += piece_data
    
    return complete_data

def main():
    print("Extracting BitTorrent pieces...")
    pieces = extract_pieces()
    
    if not pieces:
        print("No pieces found!")
        return
    
    print(f"Found {len(pieces)} pieces")
    for idx in sorted(pieces.keys()):
        print(f"Piece {idx:02x}: {len(pieces[idx])} chunks")
    
    print("\nReassembling file...")
    complete_data = reassemble_file(pieces)
    
    print(f"Total reassembled size: {len(complete_data)} bytes")
    
    # Write to file
    with open('reassembled_file.bin', 'wb') as f:
        f.write(complete_data)
    
    print("Saved as reassembled_file.bin")
    
    # Try to identify file type
    if complete_data.startswith(b'%PDF'):
        print("File appears to be a PDF!")
        with open('reassembled_file.pdf', 'wb') as f:
            f.write(complete_data)
        print("Also saved as reassembled_file.pdf")

if __name__ == "__main__":
    main()