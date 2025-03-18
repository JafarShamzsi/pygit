import sys
import os
import zlib
import hashlib
import time
import urllib.request
import struct
from pathlib import Path


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!", file=sys.stderr)

    command = sys.argv[1]
    if command == "init":
        os.mkdir(".git")
        os.mkdir(".git/objects")
        os.mkdir(".git/refs")
        with open(".git/HEAD", "w") as f:
            f.write("ref: refs/heads/main\n")
        print("Initialized git directory")
    elif command == "cat-file" and len(sys.argv) > 3 and sys.argv[2] == "-p":
        object_hash = sys.argv[3]
        cat_file(object_hash)
    elif command == "hash-object" and "-w" in sys.argv and len(sys.argv) > 3:
        file_path = sys.argv[sys.argv.index("-w") + 1] if sys.argv.index("-w") < len(sys.argv) - 1 else sys.argv[-1]
        print(hash_object(file_path, write=True))
    elif command == "ls-tree" and "--name-only" in sys.argv and len(sys.argv) > 3:
        tree_hash = sys.argv[-1]
        ls_tree(tree_hash, name_only=True)
    elif command == "write-tree":
        print(write_tree())
    elif command == "commit-tree":
        # Parse arguments
        tree_sha = sys.argv[2]
        parent_sha = None
        message = None
        
        # Find -p and -m arguments
        for i in range(3, len(sys.argv)):
            if sys.argv[i] == "-p" and i + 1 < len(sys.argv):
                parent_sha = sys.argv[i + 1]
            elif sys.argv[i] == "-m" and i + 1 < len(sys.argv):
                message = sys.argv[i + 1]
        
        # Create commit and print hash
        print(commit_tree(tree_sha, parent_sha, message))
    elif command == "clone":
        url = sys.argv[2]
        target_dir = sys.argv[3]
        clone_repository(url, target_dir)
    else:
        raise RuntimeError(f"Unknown command #{command}")


def cat_file(object_hash):
    # Construct the path to the object file
    # Path format: .git/objects/<first-2-chars>/<remaining-38-chars>
    object_dir = os.path.join(".git", "objects", object_hash[:2])
    object_path = os.path.join(object_dir, object_hash[2:])
    
    # Read and decompress the object
    with open(object_path, "rb") as f:
        compressed_data = f.read()
    
    decompressed_data = zlib.decompress(compressed_data)
    
    # Find the null byte that separates header from content
    null_byte_index = decompressed_data.find(b'\x00')
    if null_byte_index == -1:
        raise RuntimeError("Invalid git object: missing null byte separator")
    
    # Parse header (format: "blob <size>\0<content>")
    header = decompressed_data[:null_byte_index].decode()
    if not header.startswith("blob "):
        raise RuntimeError(f"Expected a blob object, got: {header.split()[0]}")
    
    # Extract and output content without adding a newline
    content = decompressed_data[null_byte_index + 1:]
    sys.stdout.buffer.write(content)


def ls_tree(tree_hash, name_only=False):
    """
    List the contents of a tree object.
    If name_only is True, only print the names of the entries.
    """
    # Construct the path to the object file
    object_dir = os.path.join(".git", "objects", tree_hash[:2])
    object_path = os.path.join(object_dir, tree_hash[2:])
    
    # Read and decompress the object
    with open(object_path, "rb") as f:
        compressed_data = f.read()
    
    decompressed_data = zlib.decompress(compressed_data)
    
    # Find the null byte that separates header from content
    null_byte_index = decompressed_data.find(b'\x00')
    if null_byte_index == -1:
        raise RuntimeError("Invalid git object: missing null byte separator")
    
    # Parse header (format: "tree <size>\0<content>")
    header = decompressed_data[:null_byte_index].decode()
    if not header.startswith("tree "):
        raise RuntimeError(f"Expected a tree object, got: {header.split()[0]}")
    
    # Extract content (everything after the header)
    content = decompressed_data[null_byte_index + 1:]
    
    # Parse tree entries
    # Format: <mode> <name>\0<20_byte_sha> (repeated)
    entries = []
    i = 0
    while i < len(content):
        # Find the space that separates mode from name
        space_index = content.find(b' ', i)
        if space_index == -1:
            break
        
        # Extract mode
        mode = content[i:space_index].decode()
        
        # Find the null byte that separates name from SHA
        null_byte_index = content.find(b'\x00', space_index)
        if null_byte_index == -1:
            break
        
        # Extract name
        name = content[space_index + 1:null_byte_index].decode()
        
        # Extract SHA (20 bytes after the null byte)
        sha_bytes = content[null_byte_index + 1:null_byte_index + 21]
        sha_hex = sha_bytes.hex()
        
        # Add to entries
        entries.append((mode, name, sha_hex))
        
        # Move to next entry
        i = null_byte_index + 21
    
    # Print entries
    if name_only:
        for _, name, _ in entries:
            print(name)
    else:
        for mode, name, sha in entries:
            # Format the mode with leading zeros
            formatted_mode = mode.zfill(6)
            
            # Determine if it's a blob or tree
            obj_type = "tree" if mode == "40000" else "blob"
            
            print(f"{formatted_mode} {obj_type} {sha}\t{name}")


def hash_object(file_path, write=False):
    """
    Compute the hash of a file and optionally write it to the Git object store.
    Returns the SHA-1 hash as a hex string.
    """
    # Read file content
    with open(file_path, 'rb') as f:
        content = f.read()
    
    # Create the blob header: "blob <size>\0"
    header = f"blob {len(content)}".encode() + b'\x00'
    
    # Compute SHA-1 hash of header + content
    sha = hashlib.sha1(header + content).hexdigest()
    
    if write:
        # Create directory structure if it doesn't exist
        object_dir = os.path.join(".git", "objects", sha[:2])
        if not os.path.exists(object_dir):
            os.makedirs(object_dir)
        
        object_path = os.path.join(object_dir, sha[2:])
        
        # Write compressed object to file
        with open(object_path, 'wb') as f:
            compressed_data = zlib.compress(header + content)
            f.write(compressed_data)
    
    return sha


def write_tree():
    """
    Write the current directory as a tree object to the Git object store.
    Returns the SHA-1 hash of the tree object.
    """
    return write_tree_recursive(".")


def write_tree_recursive(directory):
    """
    Recursively write a directory as a tree object to the Git object store.
    Returns the SHA-1 hash of the tree object.
    """
    entries = []
    
    # Get a sorted list of entries (excluding .git)
    dir_entries = sorted(os.listdir(directory))
    
    for item in dir_entries:
        # Skip .git directory
        if item == ".git":
            continue
            
        path = os.path.join(directory, item)
        
        if os.path.isdir(path):
            # For directories, recursively create tree objects
            mode = "40000"  # Directory mode
            sha = write_tree_recursive(path)
            # Convert hex SHA to binary
            sha_binary = bytes.fromhex(sha)
        else:
            # For files, use hash_object
            if os.access(path, os.X_OK):
                mode = "100755"  # Executable file mode
            else:
                mode = "100644"  # Regular file mode
            
            sha = hash_object(path, write=True)
            # Convert hex SHA to binary
            sha_binary = bytes.fromhex(sha)
            
        # Create entry: <mode> <name>\0<20_byte_sha>
        entry = f"{mode} {item}".encode() + b'\0' + sha_binary
        entries.append(entry)
    
    # Concatenate all entries
    tree_content = b"".join(entries)
    
    # Create the tree header: "tree <size>\0"
    tree_header = f"tree {len(tree_content)}".encode() + b'\0'
    
    # Compute the SHA-1 hash
    sha = hashlib.sha1(tree_header + tree_content).hexdigest()
    
    # Write the tree object
    object_dir = os.path.join(".git", "objects", sha[:2])
    if not os.path.exists(object_dir):
        os.makedirs(object_dir)
    
    object_path = os.path.join(object_dir, sha[2:])
    
    with open(object_path, 'wb') as f:
        compressed_data = zlib.compress(tree_header + tree_content)
        f.write(compressed_data)
    
    return sha


def commit_tree(tree_sha, parent_sha, message):
    """
    Create a commit object with the given tree SHA, parent commit SHA, and message.
    Returns the SHA-1 hash of the commit object.
    """
    # Get current timestamp
    timestamp = int(time.time())
    timezone = "-0500"  # Example timezone offset
    
    # Author and committer information
    author = "GitHub Copilot <copilot@github.com>"
    committer = "GitHub Copilot <copilot@github.com>"
    
    # Build commit content
    content = f"tree {tree_sha}\n"
    if parent_sha:
        content += f"parent {parent_sha}\n"
    content += f"author {author} {timestamp} {timezone}\n"
    content += f"committer {committer} {timestamp} {timezone}\n"
    content += f"\n{message}\n"
    
    # Create the commit header: "commit <size>\0"
    header = f"commit {len(content)}".encode() + b'\x00'
    
    # Add content as bytes
    commit_data = header + content.encode()
    
    # Compute SHA-1 hash
    sha = hashlib.sha1(commit_data).hexdigest()
    
    # Write the commit object
    object_dir = os.path.join(".git", "objects", sha[:2])
    if not os.path.exists(object_dir):
        os.makedirs(object_dir)
    
    object_path = os.path.join(object_dir, sha[2:])
    
    with open(object_path, 'wb') as f:
        compressed_data = zlib.compress(commit_data)
        f.write(compressed_data)
    
    return sha


def clone_repository(url, target_dir):
    """
    Clone a Git repository from a URL into the target directory.
    """
    parent = Path(target_dir)
    
    # Initialize new repository
    parent.mkdir(parents=True, exist_ok=True)
    (parent / ".git").mkdir(parents=True)
    (parent / ".git" / "objects").mkdir(parents=True)
    (parent / ".git" / "refs").mkdir(parents=True)
    (parent / ".git" / "refs" / "heads").mkdir(parents=True)
    (parent / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    
    # Fetch refs
    req = urllib.request.Request(f"{url}/info/refs?service=git-upload-pack")
    with urllib.request.urlopen(req) as f:
        refs_data = f.read()
    
    # Parse refs
    refs = {}
    for line in refs_data.split(b'\n'):
        if not line.startswith(b'#') and len(line) > 4:
            line = line[4:]  # Skip the length prefix
            if not line:
                continue
                
            parts = line.split(b'\0')[0]
            if parts.endswith(b'HEAD'):
                parts = parts[4:]  # Skip "HEAD"
            else:
                parts = parts
                
            if b' ' in parts:
                sha, name = parts.split(b' ')
                refs[name.decode()] = sha.decode()
    
    # Write refs to the local repository
    for name, sha in refs.items():
        ref_path = parent / ".git" / name
        ref_path.parent.mkdir(parents=True, exist_ok=True)
        ref_path.write_text(sha + '\n')
    
    # Fetch packfile
    body = (
        b"0011command=fetch0001000fno-progress"
        + b"".join(b"0032want " + ref.encode() + b"\n" for ref in refs.values())
        + b"0009done\n0000"
    )
    
    req = urllib.request.Request(
        f"{url}/git-upload-pack",
        data=body,
        headers={"Git-Protocol": "version=2"},
    )
    
    with urllib.request.urlopen(req) as f:
        pack_bytes = f.read()
    
    # Parse packfile
    pack_lines = []
    while pack_bytes:
        line_len = int(pack_bytes[:4], 16)
        if line_len == 0:
            break
        pack_lines.append(pack_bytes[4:line_len])
        pack_bytes = pack_bytes[line_len:]
    
    # Join pack data, skipping the first line (header)
    pack_file = b"".join(l[1:] for l in pack_lines[1:])
    
    # Skip packfile header and version
    pack_file = pack_file[8:]
    
    # Read number of objects
    n_objs, = struct.unpack("!I", pack_file[:4])
    pack_file = pack_file[4:]
    
    print(f"Processing {n_objs} objects from packfile...", file=sys.stderr)
    
    # Process each object in the packfile
    for _ in range(n_objs):
        ty, size, pack_file = next_size_type(pack_file)
        
        if ty in ["commit", "tree", "blob", "tag"]:
            # Direct object
            dec = zlib.decompressobj()
            content = dec.decompress(pack_file)
            pack_file = dec.unused_data
            
            # Write object to git repository
            write_object_raw(parent, ty, content)
            
        elif ty == "ref_delta":
            # Reference delta object
            obj = pack_file[:20].hex()
            pack_file = pack_file[20:]
            
            dec = zlib.decompressobj()
            delta = dec.decompress(pack_file)
            pack_file = dec.unused_data
            
            # Get the base object
            base_ty, base_content = read_object(parent, obj)
            
            # Parse delta header
            source_size, delta = next_size_delta(delta)
            target_size, delta = next_size_delta(delta)
            
            # Apply delta to base content
            target_content = apply_delta(delta, base_content)
            
            # Write the reconstructed object
            write_object_raw(parent, base_ty, target_content)
        else:
            raise RuntimeError(f"Unsupported object type: {ty}")
    
    # Checkout the working tree
    print("Checking out files...", file=sys.stderr)
    head_ref = (parent / ".git" / "HEAD").read_text().strip()
    if head_ref.startswith("ref: "):
        head_ref = head_ref[5:]  # Skip "ref: "
        head_sha = (parent / ".git" / head_ref).read_text().strip()
    else:
        head_sha = head_ref
    
    # Read the commit to get the tree
    _, commit_content = read_object(parent, head_sha)
    tree_sha = commit_content.split(b'\n')[0][5:].decode()
    
    # Render tree
    render_tree(parent, parent, tree_sha)
    
    print(f"Successfully cloned into {target_dir}", file=sys.stderr)


def next_size_type(bs):
    """Parse the type and size from a packfile object header."""
    # Extract type (bits 4-6)
    ty_num = (bs[0] & 0b01110000) >> 4
    
    # Map type number to string
    ty_map = {
        1: "commit",
        2: "tree",
        3: "blob",
        4: "tag",
        6: "ofs_delta",
        7: "ref_delta"
    }
    ty = ty_map.get(ty_num, "unknown")
    
    # Extract size (initial 4 bits + variable length encoding)
    size = bs[0] & 0b00001111
    i = 1
    shift = 4
    
    # Parse variable-length size encoding
    while bs[i-1] & 0b10000000:
        size |= (bs[i] & 0b01111111) << shift
        shift += 7
        i += 1
    
    return ty, size, bs[i:]


def next_size_delta(bs):
    """Parse a size value from delta encoding."""
    size = bs[0] & 0b01111111
    i = 1
    shift = 7
    
    # Parse variable-length size encoding
    while bs[i-1] & 0b10000000:
        size |= (bs[i] & 0b01111111) << shift
        shift += 7
        i += 1
    
    return size, bs[i:]


def apply_delta(delta, base_content):
    """Apply a delta to a base object to produce a new object."""
    result = bytearray()
    
    while delta:
        # Check instruction type
        cmd = delta[0]
        delta = delta[1:]
        
        if cmd & 0b10000000:  # Copy instruction
            # Parse copy offset and size
            copy_offset = 0
            copy_size = 0
            pos = 0
            
            # Read offset if corresponding bit is set
            for i in range(4):
                if cmd & (1 << i):
                    copy_offset |= delta[pos] << (i * 8)
                    pos += 1
            
            # Read size if corresponding bit is set
            for i in range(3):
                if cmd & (1 << (i + 4)):
                    copy_size |= delta[pos] << (i * 8)
                    pos += 1
            
            # Default size is 0x10000 if no size bits are set
            if copy_size == 0:
                copy_size = 0x10000
            
            # Copy data from base content
            result.extend(base_content[copy_offset:copy_offset + copy_size])
            delta = delta[pos:]
        else:  # Insert instruction
            # Copy data directly from delta
            result.extend(delta[:cmd])
            delta = delta[cmd:]
    
    return bytes(result)


def read_object(parent, sha):
    """Read an object from the Git object store."""
    obj_path = parent / ".git" / "objects" / sha[:2] / sha[2:]
    with open(obj_path, 'rb') as f:
        data = zlib.decompress(f.read())
    
    # Split header and content
    null_pos = data.find(b'\0')
    header = data[:null_pos]
    content = data[null_pos + 1:]
    
    # Parse type
    ty, _ = header.split(b' ', 1)
    
    return ty.decode(), content


def write_object_raw(parent, ty, content):
    """Write a Git object directly to the object store."""
    # Create object data with header
    data = f"{ty} {len(content)}".encode() + b'\0' + content
    
    # Compute SHA-1 hash
    sha = hashlib.sha1(data).hexdigest()
    
    # Ensure directory exists
    obj_dir = parent / ".git" / "objects" / sha[:2]
    obj_dir.mkdir(parents=True, exist_ok=True)
    
    # Write compressed object
    with open(obj_dir / sha[2:], 'wb') as f:
        f.write(zlib.compress(data))
    
    return sha


def render_tree(repo_root, target_dir, tree_sha):
    """Render a tree object to the filesystem."""
    _, tree_content = read_object(repo_root, tree_sha)
    
    # Parse tree entries
    i = 0
    while i < len(tree_content):
        # Find space between mode and name
        space_pos = tree_content.find(b' ', i)
        if space_pos == -1:
            break
        
        # Extract mode
        mode = tree_content[i:space_pos]
        
        # Find null byte between name and SHA
        null_pos = tree_content.find(b'\0', space_pos)
        if null_pos == -1:
            break
        
        # Extract name
        name = tree_content[space_pos+1:null_pos].decode()
        
        # Extract SHA (20 bytes)
        sha = tree_content[null_pos+1:null_pos+21].hex()
        
        # Create file or directory based on mode
        path = target_dir / name
        
        if mode == b'40000':  # Directory
            # Create directory and render its contents
            path.mkdir(exist_ok=True)
            render_tree(repo_root, path, sha)
        else:  # File
            # Get file contents
            _, content = read_object(repo_root, sha)
            
            # Write file
            path.write_bytes(content)
            
            # Set executable bit if mode is 100755
            if mode == b'100755':
                path.chmod(0o755)
        
        # Move to next entry
        i = null_pos + 21


if __name__ == "__main__":
    main()
