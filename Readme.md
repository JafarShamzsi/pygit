# PyGit - Git Implementation in Python

A lightweight Git implementation written from scratch in Python. This project recreates core Git functionality to demonstrate Git's internal architecture and object model.

## Features

- **Git Object Management**
  - Blobs (file contents)
  - Trees (directory structures)
  - Commits (snapshots with metadata)

- **Core Git Commands**
  - `init` - Initialize a new repository
  - `cat-file` - Display object contents
  - `hash-object` - Compute hash and optionally create blob objects
  - `ls-tree` - List tree object contents
  - `write-tree` - Create a tree object from the working directory
  - `commit-tree` - Create a commit object
  - `clone` - Clone a remote repository via HTTP
  - `branch` - List, create, or delete branches
  - `checkout` - Switch branches or restore working tree files
  - `log` - Show commit logs
  - `status` - Show working tree status
  - `config` - Get and set repository options
  - `remote` - Manage set of tracked repositories

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pygit.git
cd pygit

# No additional dependencies required - uses standard Python libraries
```

## Usage

```bash
# Initialize a new repository
python app/main.py init

# Create a blob object from a file
python app/main.py hash-object -w myfile.txt

# Display the contents of a Git object
python app/main.py cat-file -p <object-hash>

# Create a tree object from the current directory
python app/main.py write-tree

# List the contents of a tree object
python app/main.py ls-tree --name-only <tree-hash>

# Create a commit object
python app/main.py commit-tree <tree-hash> -p <parent-commit-hash> -m "Commit message"

# Clone a repository
python app/main.py clone https://github.com/username/repo.git target-dir

# Branch operations
python app/main.py branch                    # List all branches
python app/main.py branch new-branch         # Create a new branch
python app/main.py branch -d branch-to-delete # Delete a branch

# Checkout a branch or commit
python app/main.py checkout branch-name
python app/main.py checkout <commit-hash>    # Results in detached HEAD

# View commit history
python app/main.py log
python app/main.py log -n 5                  # Limit to 5 most recent commits
```

## How It Works

### Git Objects

PyGit implements Git's content-addressable storage model using three primary object types:

1. **Blobs**: Store file contents with a header format of `blob <size>\0<content>`
2. **Trees**: Store directory structures with entries in the format `<mode> <name>\0<20-byte-SHA>`
3. **Commits**: Store metadata about changes with author, committer, tree reference, and parent commit(s)

All objects are compressed with zlib and stored in `.git/objects/<first-2-chars>/<remaining-38-chars>`.

### Branch Management

The implementation includes full branch management capabilities:
- Creating branches at the current HEAD
- Listing all branches with the current branch marked
- Deleting branches (with safety checks to prevent deleting the current branch)
- Reference resolution to find commit objects from branch names

### Repository Cloning

The implementation includes:
- Smart HTTP protocol support
- Packfile parsing and extraction
- Delta reconstruction for efficient network transfer
- Working tree checkout from commit tree

### Error Handling

The code includes robust error handling for:
- Repository validity checks
- Object existence and validity
- Network operations during cloning
- Permission and file system errors
- User input validation

## Technical Highlights

- SHA-1 content-addressing for all Git objects
- zlib compression for efficient storage
- Binary packfile parsing with variable-length encoding
- Delta reconstruction algorithms
- Recursive tree traversal for directory operations
- Reference management for branches and HEAD

## Educational Value

This project demonstrates:
- How Git's object model works internally
- The structure and format of Git objects
- Git's network protocols for repository transfer
- Branch management and HEAD references
- Practical implementation of content-addressable storage

## Limitations

This implementation is for educational purposes and lacks some of Git's advanced features:
- No index/staging area support
- Limited reference management
- No merge operations
- Basic authentication only
- Simplified status implementation
- No stashing support

## Future Improvements

Potential enhancements for this project:
- Add staging area/index support
- Implement merge functionality
- Add tag support
- Improve status command with detailed file state reporting
- Add support for submodules
- Implement stashing functionality
