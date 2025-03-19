import sys
import os
import zlib
import hashlib
import time
import urllib.request
import struct
from pathlib import Path


def error(message, exit_code=1):
    """Print error message to stderr and exit with specified code."""
    print(f"error: {message}", file=sys.stderr)
    sys.exit(exit_code)


def validate_git_repository():
    """Ensure we're in a valid Git repository."""
    if not os.path.isdir(".git"):
        error("not a git repository (or any of the parent directories)")
    
    required_paths = [
        ".git/objects",
        ".git/refs",
        ".git/HEAD"
    ]
    
    for path in required_paths:
        if not os.path.exists(path):
            error(f"corrupt git repository: {path} not found")


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!", file=sys.stderr)

    if len(sys.argv) < 2:
        error("No command specified")
    
    command = sys.argv[1]
    
    try:
        if command == "init":
            try:
                os.mkdir(".git")
                os.mkdir(".git/objects")
                os.mkdir(".git/refs")
                with open(".git/HEAD", "w") as f:
                    f.write("ref: refs/heads/main\n")
                print("Initialized git directory")
            except FileExistsError:
                error("Git repository already exists")
            except PermissionError:
                error("Permission denied")
                
        elif command == "cat-file" and len(sys.argv) > 3 and sys.argv[2] == "-p":
            object_hash = sys.argv[3]
            cat_file(object_hash)
            
        elif command == "hash-object" and "-w" in sys.argv and len(sys.argv) > 3:
            file_path = sys.argv[sys.argv.index("-w") + 1] if sys.argv.index("-w") < len(sys.argv) - 1 else sys.argv[-1]
            try:
                print(hash_object(file_path, write=True))
            except FileNotFoundError:
                error(f"Cannot open '{file_path}': No such file")
                
        elif command == "ls-tree" and "--name-only" in sys.argv and len(sys.argv) > 3:
            tree_hash = sys.argv[-1]
            ls_tree(tree_hash, name_only=True)
            
        elif command == "write-tree":
            print(write_tree())
            
        elif command == "commit-tree":
            # Parse arguments
            if len(sys.argv) < 3:
                error("tree argument required")
                
            tree_sha = sys.argv[2]
            parent_sha = None
            message = None
            
            # Find -p and -m arguments
            for i in range(3, len(sys.argv)):
                if sys.argv[i] == "-p" and i + 1 < len(sys.argv):
                    parent_sha = sys.argv[i + 1]
                elif sys.argv[i] == "-m" and i + 1 < len(sys.argv):
                    message = sys.argv[i + 1]
            
            if message is None:
                error("message argument required")
                
            # Create commit and print hash
            print(commit_tree(tree_sha, parent_sha, message))
            
        elif command == "clone":
            if len(sys.argv) < 4:
                error("URL and directory arguments required")
                
            url = sys.argv[2]
            target_dir = sys.argv[3]
            clone_repository(url, target_dir)
            
        elif command == "branch":
            branch_command(sys.argv[2:])
            
        elif command == "checkout":
            if len(sys.argv) < 3:
                error("branch/commit argument required")
                
            checkout(sys.argv[2])
            
        elif command == "log":
            log_command(sys.argv[2:])
            
        elif command == "status":
            status_command()
            
        elif command == "config":
            config_command(sys.argv[2:])
            
        elif command == "remote":
            remote_command(sys.argv[2:])
            
        else:
            error(f"Unknown command '{command}'")
            
    except KeyboardInterrupt:
        sys.exit(130)  # Standard exit code for Ctrl+C
    except Exception as e:
        error(f"Unexpected error: {str(e)}")


def cat_file(object_hash):
    """Display the contents of a Git object."""
    validate_git_repository()
    
    # Validate hash format
    if not all(c in "0123456789abcdef" for c in object_hash) or len(object_hash) != 40:
        error(f"invalid object name: '{object_hash}'")
    
    # Construct object path
    object_dir = os.path.join(".git", "objects", object_hash[:2])
    object_path = os.path.join(object_dir, object_hash[2:])
    
    try:
        # Read and decompress the object
        with open(object_path, "rb") as f:
            compressed_data = f.read()
    except FileNotFoundError:
        error(f"object '{object_hash}' not found")
    except PermissionError:
        error(f"permission denied accessing object: '{object_hash}'")
    
    try:
        decompressed_data = zlib.decompress(compressed_data)
    except zlib.error:
        error(f"object '{object_hash}' is corrupted or not a valid git object")
    
    # Find null byte separator
    null_byte_index = decompressed_data.find(b'\x00')
    if null_byte_index == -1:
        error(f"object '{object_hash}' has invalid format: missing null byte separator")
    
    # Parse header
    try:
        header = decompressed_data[:null_byte_index].decode()
        obj_type = header.split()[0]
    except (UnicodeDecodeError, IndexError):
        error(f"object '{object_hash}' has invalid header format")
    
    # Output content based on object type
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


def write_tree(write=True):
    """
    Write the current directory as a tree object to the Git object store.
    
    Args:
        write (bool): Whether to actually write the tree object
    
    Returns:
        str: The SHA-1 hash of the tree object
    """
    return write_tree_recursive(".", write)


def write_tree_recursive(directory, write):
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
            sha = write_tree_recursive(path, write)
            # Convert hex SHA to binary
            sha_binary = bytes.fromhex(sha)
        else:
            # For files, use hash_object
            if os.access(path, os.X_OK):
                mode = "100755"  # Executable file mode
            else:
                mode = "100644"  # Regular file mode
            
            sha = hash_object(path, write)
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
    
    if write:
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
    """Clone a Git repository from a URL into the target directory."""
    parent = Path(target_dir)
    
    # Check if directory already exists and is not empty
    if parent.exists() and any(parent.iterdir()):
        error(f"destination path '{target_dir}' already exists and is not an empty directory")
    
    try:
        # Initialize new repository
        parent.mkdir(parents=True, exist_ok=True)
        (parent / ".git").mkdir(parents=True)
        (parent / ".git" / "objects").mkdir(parents=True)
        (parent / ".git" / "refs").mkdir(parents=True)
        (parent / ".git" / "refs" / "heads").mkdir(parents=True)
        (parent / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    except PermissionError:
        error(f"permission denied creating repository structure in '{target_dir}'")
    except OSError as e:
        error(f"failed to create repository: {str(e)}")
    
    # Fetch refs
    print(f"Cloning from {url} into {target_dir}...", file=sys.stderr)
    try:
        req = urllib.request.Request(f"{url}/info/refs?service=git-upload-pack")
        with urllib.request.urlopen(req, timeout=30) as f:
            refs_data = f.read()
    except urllib.error.URLError as e:
        error(f"failed to fetch refs: {str(e.reason)}")
    except urllib.error.HTTPError as e:
        error(f"HTTP error: {e.code} {e.reason}")
    except TimeoutError:
        error("connection timed out")
    
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


def get_current_branch():
    """Get the name of the current branch or None if in detached HEAD state."""
    validate_git_repository()
    
    try:
        with open(".git/HEAD", "r") as f:
            head_content = f.read().strip()
        
        if head_content.startswith("ref: refs/heads/"):
            return head_content[16:]
        return None  # Detached HEAD
    except FileNotFoundError:
        error("HEAD file missing")
    except IOError:
        error("couldn't read HEAD file")


def branch_command(args):
    """Handle git branch command with various options."""
    validate_git_repository()
    
    # Create branch directory if it doesn't exist
    heads_dir = Path(".git/refs/heads")
    heads_dir.mkdir(exist_ok=True)
    
    # Parse options
    delete_branch = "-d" in args or "--delete" in args
    list_branches = not args or (len(args) == 1 and args[0] in ["-d", "--delete"])
    
    if delete_branch:
        # Get branch name to delete
        try:
            if args[args.index("-d" if "-d" in args else "--delete") + 1:]:
                branch_name = args[args.index("-d" if "-d" in args else "--delete") + 1]
            else:
                error("branch name required")
        except IndexError:
            error("branch name required")
            
        branch_path = heads_dir / branch_name
        if not branch_path.exists():
            error(f"branch '{branch_name}' not found")
            
        current = get_current_branch()
        if current == branch_name:
            error(f"cannot delete branch '{branch_name}' checked out")
            
        try:
            branch_path.unlink()
            print(f"Deleted branch {branch_name}")
        except OSError:
            error(f"could not delete branch '{branch_name}'")
    
    elif list_branches:
        # List all branches
        current = get_current_branch()
        branches = sorted([p.name for p in heads_dir.iterdir() if p.is_file()])
        
        for branch in branches:
            prefix = "* " if branch == current else "  "
            print(f"{prefix}{branch}")
    
    else:
        # Create new branch
        branch_name = args[0]
        
        # Get current HEAD commit
        current_commit = resolve_ref("HEAD")
        if not current_commit:
            error("failed to get HEAD commit")
        
        branch_path = heads_dir / branch_name
        if branch_path.exists():
            error(f"branch '{branch_name}' already exists")
        
        try:
            with open(branch_path, "w") as f:
                f.write(f"{current_commit}\n")
            print(f"Created branch {branch_name}")
        except IOError:
            error(f"could not create branch '{branch_name}'")


def resolve_ref(ref_name):
    """Resolve a reference to its commit SHA."""
    validate_git_repository()
    
    try:
        # Direct reference to a commit
        if all(c in "0123456789abcdef" for c in ref_name) and len(ref_name) == 40:
            return ref_name
        
        # HEAD reference
        if ref_name == "HEAD":
            with open(".git/HEAD", "r") as f:
                head_content = f.read().strip()
            
            if head_content.startswith("ref: "):
                ref_path = head_content[5:]  # Skip "ref: "
                return resolve_ref(ref_path)
            else:
                # Detached HEAD
                return head_content
        
        # Branch reference
        if not ref_name.startswith("refs/"):
            # Try as a branch name
            branch_path = f".git/refs/heads/{ref_name}"
            if os.path.exists(branch_path):
                with open(branch_path, "r") as f:
                    return f.read().strip()
            
            # Not found as branch, try full reference path
            ref_path = f".git/refs/{ref_name}"
        else:
            ref_path = f".git/{ref_name}"
        
        if os.path.exists(ref_path):
            with open(ref_path, "r") as f:
                return f.read().strip()
        
        return None
    except (FileNotFoundError, IOError):
        return None


def checkout(target):
    """
    Check out a branch or commit.
    
    Args:
        target (str): Branch name or commit hash to checkout
    """
    validate_git_repository()
    
    # Resolve the target to a commit SHA
    commit_sha = resolve_ref(target)
    if not commit_sha:
        error(f"pathspec '{target}' did not match any file(s) known to git")
    
    # Get the tree SHA from the commit
    try:
        _, commit_content = read_object(Path("."), commit_sha)
        tree_sha = commit_content.split(b'\n')[0][5:].decode()
    except Exception:
        error(f"failed to get tree from commit '{commit_sha}'")
    
    # Check for uncommitted changes
    if has_uncommitted_changes():
        error("Your local changes would be overwritten by checkout.\n"
              "Please commit your changes or stash them before you switch branches.")
    
    # Update HEAD
    is_branch = os.path.exists(f".git/refs/heads/{target}")
    try:
        with open(".git/HEAD", "w") as f:
            if is_branch:
                f.write(f"ref: refs/heads/{target}\n")
            else:
                # Detached HEAD state
                f.write(f"{commit_sha}\n")
    except IOError:
        error("failed to update HEAD")
    
    # Clean working directory
    working_dir = Path(".")
    for item in working_dir.iterdir():
        if item.name != ".git":
            if item.is_dir():
                import shutil
                shutil.rmtree(item)
            else:
                item.unlink()
    
    # Render the tree
    render_tree(Path("."), working_dir, tree_sha)
    
    if is_branch:
        print(f"Switched to branch '{target}'")
    else:
        print(f"Note: checking out '{commit_sha[:7]}'")
        print("You are in 'detached HEAD' state.")


def has_uncommitted_changes():
    """
    Check if there are uncommitted changes in the working directory.
    
    Returns:
        bool: True if there are uncommitted changes
    """
    # This is a simplified version - a real implementation would compare
    # the working directory with the index and HEAD tree
    current_tree = write_tree(write=False)
    head_tree = None
    
    try:
        head_commit = resolve_ref("HEAD")
        if head_commit:
            _, commit_content = read_object(Path("."), head_commit)
            head_tree = commit_content.split(b'\n')[0][5:].decode()
    except Exception:
        # If we can't get HEAD tree, assume there are changes
        return True
    
    # If we don't have a HEAD tree, there's no uncommitted changes
    if not head_tree:
        return False
    
    return current_tree != head_tree


def log_command(args):
    """
    Show commit logs.
    
    Args:
        args (list): Command arguments
    """
    validate_git_repository()
    
    # Parse options
    commit_limit = None
    for i, arg in enumerate(args):
        if arg == "-n" and i+1 < len(args):
            try:
                commit_limit = int(args[i+1])
            except ValueError:
                error(f"invalid number: '{args[i+1]}'")
    
    # Start from HEAD
    current_commit = resolve_ref("HEAD")
    if not current_commit:
        error("HEAD not found")
    
    # Display commit history
    displayed = 0
    while current_commit and (commit_limit is None or displayed < commit_limit):
        try:
            # Get commit object
            commit_type, commit_content = read_object(Path("."), current_commit)
            if commit_type != "commit":
                error(f"object {current_commit} is not a commit")
            
            # Parse commit content
            commit_lines = commit_content.split(b'\n')
            
            # Extract commit metadata
            tree_line = next((l for l in commit_lines if l.startswith(b'tree')), None)
            author_line = next((l for l in commit_lines if l.startswith(b'author')), None)
            parent_line = next((l for l in commit_lines if l.startswith(b'parent')), None)
            
            if not tree_line or not author_line:
                error(f"malformed commit object: {current_commit}")
            
            # Format author info
            author_info = author_line.decode('utf-8', 'replace')
            author_parts = author_info.split(" ")
            
            if len(author_parts) >= 3:
                # Extract timestamp
                try:
                    author_time = int(author_parts[-2])
                    author_date = time.strftime("%a %b %d %H:%M:%S %Y %z", time.localtime(author_time))
                except (ValueError, IndexError):
                    author_date = "unknown date"
                
                # Get author name by removing "author " prefix and timestamp/timezone
                author_name = " ".join(author_parts[1:-2])
            else:
                author_name = "Unknown"
                author_date = "unknown date"
            
            # Get commit message (everything after the blank line)
            message_start = 0
            for i, line in enumerate(commit_lines):
                if line == b'':
                    message_start = i + 1
                    break
            
            commit_message = b'\n'.join(commit_lines[message_start:])
            
            # Print commit info
            print(f"commit {current_commit}")
            print(f"Author: {author_name}")
            print(f"Date:   {author_date}")
            print()
            print(f"    {commit_message.decode('utf-8', 'replace')}")
            print()
            
            displayed += 1
            
            # Move to parent commit if available
            if parent_line:
                current_commit = parent_line.split()[1].decode()
            else:
                current_commit = None
                
        except Exception as e:
            error(f"failed to read commit {current_commit}: {str(e)}")


def status_command():
    """Show the working tree status."""
    validate_git_repository()
    
    # Get current branch
    branch = get_current_branch()
    if branch:
        print(f"On branch {branch}")
    else:
        print("HEAD detached at", resolve_ref("HEAD")[:7])
    
    # Compare working dir with HEAD
    # ... implementation would identify modified/new/deleted files ...
    
    # This requires a more extensive implementation to compare trees


def config_command(args):
    """Get and set repository or global options."""
    # Determine if we're setting or getting
    if len(args) == 2:
        # Setting a config value
        key, value = args
        set_config_value(key, value)
    elif len(args) == 1:
        # Getting a config value
        key = args[0]
        value = get_config_value(key)
        if value:
            print(value)
    else:
        error("incorrect number of arguments")


def remote_command(args):
    """Manage set of tracked repositories."""
    if not args:
        # List remotes
        list_remotes()
    elif args[0] == "add" and len(args) >= 3:
        # Add a remote
        name, url = args[1], args[2]
        add_remote(name, url)
    else:
        error("incorrect number of arguments")


if __name__ == "__main__":
    main()
