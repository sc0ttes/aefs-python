#!/usr/bin/env python3
import os
import sys
import errno
import logging
import xattr
from fuse import FUSE, FuseOSError, Operations
from stat import S_IFDIR, S_IFREG
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)

class EncryptedFS(Operations):
    def __init__(self, encrypted_dir, decrypted_dir, public_key_path, private_key_path=None, debug=False):
        self.encrypted_dir = encrypted_dir  # Directory where encrypted files are stored
        self.root = os.path.realpath(decrypted_dir)  # Mount point directory (decrypted view)
        self.fd = 0
        self.file_handles = {}
        self.open_files = {}
        self.debug = debug

        # Determine mode based on presence of private key
        self.decryption_mode = private_key_path is not None
        self.encryption_mode = not self.decryption_mode

        if self.decryption_mode:
            log.info("Operating in Decryption Mode (Read-Only)")
        else:
            log.info("Operating in Encryption Mode (Write-Only)")

        # Load the public key
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())

        # Load the private key if provided
        if self.decryption_mode:
            with open(private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self.private_key = None

    def _full_path(self, path):
        # Access the underlying encrypted directory directly
        return os.path.join(self.encrypted_dir, path.lstrip('/'))

    def _is_key_file(self, path):
        # Identifies both standard and hidden .key files
        return path.endswith('.key') or (path.startswith('.') and path.endswith('.key'))

    # Helper function for decryption
    def _decrypt_data(self, sym_key, nonce, offset, data):
        block_size = 16  # AES block size in bytes
        # Calculate the number of blocks to skip based on the offset
        block_number = offset // block_size
        # Calculate the byte offset within the block
        byte_offset = offset % block_size

        # Initialize counter based on nonce and block number
        initial_counter = int.from_bytes(nonce, byteorder='big') + block_number
        initial_counter_bytes = initial_counter.to_bytes(len(nonce), byteorder='big')

        # Initialize cipher with adjusted counter
        cipher = Cipher(algorithms.AES(sym_key), modes.CTR(initial_counter_bytes))
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(data)

        # If there is a byte offset within the block, adjust the decrypted data accordingly
        if byte_offset:
            decrypted_data = decrypted_data[byte_offset:]
        
        return decrypted_data

    # Helper function for encryption
    def _encrypt_data(self, sym_key, nonce, offset, data):
        block_size = 16  # AES block size in bytes
        # Calculate the number of blocks to skip based on the offset
        block_number = offset // block_size
        # Calculate the byte offset within the block
        byte_offset = offset % block_size

        # Initialize counter based on nonce and block number
        initial_counter = int.from_bytes(nonce, byteorder='big') + block_number
        initial_counter_bytes = initial_counter.to_bytes(len(nonce), byteorder='big')

        # Initialize cipher with adjusted counter
        cipher = Cipher(algorithms.AES(sym_key), modes.CTR(initial_counter_bytes))
        encryptor = cipher.encryptor()

        # Encrypt the data
        encrypted_data = encryptor.update(data)

        # If there is a byte offset within the block, adjust the encrypted data accordingly
        if byte_offset:
            encrypted_data = encrypted_data[byte_offset:]
        
        return encrypted_data

    # Filesystem methods
    # ==================

    def getattr(self, path, fh=None):
        if self._is_key_file(path):
            log.warning(f"Attempted to access attributes of hidden key file: {path}")
            raise FuseOSError(errno.ENOENT)  # Treat as non-existent

        full_path = self._full_path(path)
        try:
            st = os.lstat(full_path)
            attrs = {key: getattr(st, key) for key in (
                'st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid',
                'st_gid', 'st_size', 'st_atime', 'st_mtime', 'st_ctime')}
            return attrs
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        dirents = ['.', '..']
        if os.path.isdir(full_path):
            for entry in os.listdir(full_path):
                if not self._is_key_file(entry):
                    dirents.append(entry)
        for entry in dirents:
            yield entry

    def open(self, path, flags):
        if self._is_key_file(path):
            log.warning(f"Attempted to open hidden key file: {path}")
            raise FuseOSError(errno.ENOENT)  # Treat as non-existent

        full_path = self._full_path(path)

        # Determine access mode
        mode = flags & os.O_ACCMODE

        if self.decryption_mode:
            # In decryption mode, allow only read operations
            if mode != os.O_RDONLY:
                log.warning(f"Write operation attempted in Decryption Mode for {path}")
                raise FuseOSError(errno.EACCES)  # Deny write operations
        else:
            # In encryption mode, allow only write operations
            if mode == os.O_RDONLY:
                log.warning(f"Read operation attempted in Encryption Mode for {path}")
                raise FuseOSError(errno.EACCES)  # Deny read operations

        self.fd += 1
        fh_id = self.fd

        if self.decryption_mode and mode == os.O_RDONLY:
            # Decryption logic (Read-only)
            if self.private_key:
                # Attempt to decrypt the symmetric key and nonce
                try:
                    # First, try to get from xattrs
                    enc_sym_key = xattr.getxattr(full_path, b'user.enc_sym_key')
                    nonce = xattr.getxattr(full_path, b'user.nonce')
                    log.debug(f"Retrieved enc_sym_key and nonce from xattrs for {path}")
                except (OSError, KeyError):
                    # If xattrs not found, try to read from hidden .key file
                    key_file = self._get_hidden_key_file(full_path)
                    if not os.path.exists(key_file):
                        log.error(f"Encrypted symmetric key and nonce not found for {path}")
                        raise FuseOSError(errno.EACCES)
                    try:
                        with open(key_file, 'rb') as f:
                            data = f.read()
                            # Assuming nonce is 16 bytes
                            if len(data) < 16:
                                log.error(f"Invalid key file format for {path}")
                                raise FuseOSError(errno.EACCES)
                            enc_sym_key = data[:-16]
                            nonce = data[-16:]
                            log.debug(f"Retrieved enc_sym_key and nonce from hidden key file for {path}")
                    except Exception as e:
                        log.error(f"Failed to read hidden key file for {path}: {e}")
                        raise FuseOSError(errno.EACCES)

                try:
                    sym_key = self.private_key.decrypt(
                        enc_sym_key,
                        asym_padding.OAEP(
                            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                except Exception as e:
                    log.error(f"Failed to decrypt symmetric key for {path}: {e}")
                    raise FuseOSError(errno.EACCES)

                # Open the file for reading
                try:
                    file_obj = open(full_path, 'rb')
                except Exception as e:
                    log.error(f"Failed to open file {path}: {e}")
                    raise FuseOSError(errno.EACCES)

                # Store decryption context
                self.open_files[fh_id] = {
                    'sym_key': sym_key,
                    'nonce': nonce,
                    'file_obj': file_obj
                }
            else:
                log.error("Decryption mode requires a private key.")
                raise FuseOSError(errno.EACCES)
        else:
            # Encryption logic (Write-only)
            access_mode = 'rb' if mode == os.O_RDONLY else 'r+b' if mode == os.O_RDWR else 'wb'
            try:
                file_obj = open(full_path, access_mode)
            except Exception as e:
                log.error(f"Failed to open file {path}: {e}")
                raise FuseOSError(errno.EACCES)

            self.open_files[fh_id] = {
                'file_obj': file_obj,
                'sym_key': None,
                'nonce': None
            }

        return fh_id

    def read(self, path, length, offset, fh):
        if self._is_key_file(path):
            log.warning(f"Attempted to read hidden key file: {path}")
            raise FuseOSError(errno.ENOENT)  # Treat as non-existent

        if not self.decryption_mode:
            log.warning(f"Read operation attempted in Encryption Mode for {path}")
            raise FuseOSError(errno.EACCES)  # Deny read operations

        context = self.open_files.get(fh)
        if context is None:
            raise FuseOSError(errno.EBADF)
        file_obj = context['file_obj']
        file_obj.seek(offset)
        encrypted_data = file_obj.read(length)

        if context['sym_key']:
            # Decrypt data based on the current offset
            decrypted_data = self._decrypt_data(context['sym_key'], context['nonce'], offset, encrypted_data)
            return decrypted_data
        else:
            # Return raw data if no decryption context (should not happen in decryption mode)
            return encrypted_data

    def write(self, path, data, offset, fh):
        if self._is_key_file(path):
            log.warning(f"Attempted to write to hidden key file: {path}")
            raise FuseOSError(errno.EACCES)  # Deny access

        if self.decryption_mode:
            log.warning(f"Write operation attempted in Decryption Mode for {path}")
            raise FuseOSError(errno.EACCES)  # Deny write operations

        context = self.open_files.get(fh)
        if context is None:
            raise FuseOSError(errno.EBADF)
        file_obj = context['file_obj']

        if context['sym_key'] is None:
            # Generate symmetric key and nonce
            context['sym_key'] = os.urandom(32)  # AES-256 key
            context['nonce'] = os.urandom(16)    # 16-byte nonce for CTR mode

            if self.debug:
                print(f"Symmetric Key for {path}: {context['sym_key'].hex()}")

        # Encrypt data based on the offset
        encrypted_data = self._encrypt_data(context['sym_key'], context['nonce'], offset, data)

        # Write encrypted data
        file_obj.seek(offset)
        file_obj.write(encrypted_data)

        return len(data)

    def release(self, path, fh):
        if self._is_key_file(path):
            log.warning(f"Attempted to release hidden key file: {path}")
            raise FuseOSError(errno.ENOENT)  # Treat as non-existent

        context = self.open_files.get(fh)
        if context is None:
            raise FuseOSError(errno.EBADF)
        file_obj = context['file_obj']
        file_obj.close()

        full_path = self._full_path(path)

        if self.encryption_mode and context.get('sym_key'):
            # Encrypt symmetric key with public key
            try:
                enc_sym_key = self.public_key.encrypt(
                    context['sym_key'],
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception as e:
                log.warning(f"Failed to encrypt symmetric key for {path}: {e}")
                raise FuseOSError(errno.EACCES)

            # Attempt to set xattrs
            try:
                xattr.setxattr(full_path, b'user.enc_sym_key', enc_sym_key)
                xattr.setxattr(full_path, b'user.nonce', context['nonce'])
                log.debug(f"Set xattrs for {path}")
            except OSError as e:
                log.warning(f"Failed to set xattrs for {path}: {e}")
                # Do not raise error; proceed to save to hidden .key file

            # Save encrypted symmetric key and nonce to hidden .key file
            key_file = self._get_hidden_key_file(full_path)
            try:
                with open(key_file, 'wb') as f:
                    f.write(enc_sym_key + context['nonce'])
                log.debug(f"Saved encrypted symmetric key and nonce to {key_file}")
            except OSError as e:
                log.error(f"Failed to write encrypted symmetric key and nonce to {key_file}: {e}")
                # Do not raise error

        del self.open_files[fh]
        return 0

    def create(self, path, mode, fi=None):
        if self._is_key_file(path):
            log.warning(f"Attempted to create hidden key file: {path}")
            raise FuseOSError(errno.EACCES)  # Deny creation

        if self.decryption_mode:
            log.warning(f"Create operation attempted in Decryption Mode for {path}")
            raise FuseOSError(errno.EACCES)  # Deny creation

        full_path = self._full_path(path)
        self.fd += 1
        fh_id = self.fd

        # Open file in write mode
        try:
            file_obj = open(full_path, 'wb')
        except Exception as e:
            log.error(f"Failed to create file {path}: {e}")
            raise FuseOSError(errno.EACCES)

        self.open_files[fh_id] = {
            'file_obj': file_obj,
            'sym_key': None,
            'nonce': None
        }

        return fh_id

    def unlink(self, path):
        if self._is_key_file(path):
            log.warning(f"Attempted to unlink hidden key file: {path}")
            raise FuseOSError(errno.EACCES)  # Deny deletion

        full_path = self._full_path(path)
        try:
            os.unlink(full_path)
        except OSError as e:
            raise FuseOSError(e.errno)

    def truncate(self, path, length, fh=None):
        if self._is_key_file(path):
            log.warning(f"Attempted to truncate hidden key file: {path}")
            raise FuseOSError(errno.EACCES)  # Deny truncation

        if self.decryption_mode:
            log.warning(f"Truncate operation attempted in Decryption Mode for {path}")
            raise FuseOSError(errno.EACCES)  # Deny truncation

        full_path = self._full_path(path)
        try:
            with open(full_path, 'r+b') as f:
                f.truncate(length)
        except OSError as e:
            raise FuseOSError(e.errno)

    def mkdir(self, path, mode):
        if self._is_key_file(path):
            log.warning(f"Attempted to create hidden key directory: {path}")
            raise FuseOSError(errno.EACCES)  # Deny creation

        if self.decryption_mode:
            log.warning(f"Mkdir operation attempted in Decryption Mode for {path}")
            raise FuseOSError(errno.EACCES)  # Deny creation

        full_path = self._full_path(path)
        try:
            os.mkdir(full_path, mode)
        except OSError as e:
            raise FuseOSError(e.errno)

    def rmdir(self, path):
        if self._is_key_file(path):
            log.warning(f"Attempted to remove hidden key directory: {path}")
            raise FuseOSError(errno.EACCES)  # Deny removal

        if self.decryption_mode:
            log.warning(f"Rmdir operation attempted in Decryption Mode for {path}")
            raise FuseOSError(errno.EACCES)  # Deny removal

        full_path = self._full_path(path)
        try:
            os.rmdir(full_path)
        except OSError as e:
            raise FuseOSError(e.errno)

    # xattr methods
    # ============

    def getxattr(self, path, name, position=0):
        if self._is_key_file(path):
            log.warning(f"Attempted to getxattr of hidden key file: {path}")
            raise FuseOSError(errno.ENOENT)  # Treat as non-existent

        if self.encryption_mode and name in [b'user.enc_sym_key', b'user.nonce']:
            log.warning(f"Attempted to access sensitive xattrs in Encryption Mode for {path}")
            raise FuseOSError(errno.EACCES)  # Deny access to sensitive xattrs

        full_path = self._full_path(path)
        try:
            value = xattr.getxattr(full_path, name)
            return value
        except OSError as e:
            raise FuseOSError(e.errno)

    def setxattr(self, path, name, value, options, position=0):
        if self._is_key_file(path):
            log.warning(f"Attempted to setxattr of hidden key file: {path}")
            raise FuseOSError(errno.EACCES)  # Deny setting attributes

        if self.decryption_mode and name in [b'user.enc_sym_key', b'user.nonce']:
            log.warning(f"Attempted to set sensitive xattrs in Decryption Mode for {path}")
            raise FuseOSError(errno.EACCES)  # Deny setting sensitive xattrs

        full_path = self._full_path(path)
        try:
            xattr.setxattr(full_path, name, value)
        except OSError as e:
            raise FuseOSError(e.errno)

    def listxattr(self, path):
        if self._is_key_file(path):
            log.warning(f"Attempted to listxattr of hidden key file: {path}")
            raise FuseOSError(errno.ENOENT)  # Treat as non-existent

        full_path = self._full_path(path)
        try:
            attrs = xattr.listxattr(full_path)
            # Filter out sensitive xattrs based on mode
            if self.decryption_mode:
                attrs = [attr for attr in attrs if attr not in [b'user.enc_sym_key', b'user.nonce']]
            return attrs
        except OSError as e:
            raise FuseOSError(e.errno)

    def _get_hidden_key_file(self, full_path):
        filename = os.path.basename(full_path)
        key_filename = f".{filename}.key"
        key_file = os.path.join(os.path.dirname(full_path), key_filename)
        return key_file

    def rename(self, old, new):
        if self._is_key_file(old) or self._is_key_file(new):
            log.warning(f"Attempted to rename a hidden key file: {old} to {new}")
            raise FuseOSError(errno.EACCES)  # Deny renaming of hidden key files

        old_full = self._full_path(old)
        new_full = self._full_path(new)

        try:
            os.rename(old_full, new_full)
            log.info(f"Renamed '{old}' to '{new}'")
        except OSError as e:
            log.error(f"Failed to rename '{old}' to '{new}': {e}")
            raise FuseOSError(e.errno)

        if self.encryption_mode:
            # Handle xattr renaming
            try:
                # Get xattrs from the old file
                enc_sym_key = xattr.getxattr(old_full, b'user.enc_sym_key')
                nonce = xattr.getxattr(old_full, b'user.nonce')

                # Set xattrs on the new file
                xattr.setxattr(new_full, b'user.enc_sym_key', enc_sym_key)
                xattr.setxattr(new_full, b'user.nonce', nonce)
                log.debug(f"Renamed xattrs from '{old}' to '{new}'")
            except OSError as e:
                log.warning(f"Failed to set xattrs during rename from '{old}' to '{new}': {e}")
                # Continue without raising the exception

        # Also handle hidden key file renaming if exists
        old_key_file = self._get_hidden_key_file(old_full)
        new_key_file = self._get_hidden_key_file(new_full)

        if os.path.exists(old_key_file):
            try:
                os.rename(old_key_file, new_key_file)
                log.info(f"Renamed hidden key file '{old_key_file}' to '{new_key_file}'")
            except OSError as e:
                log.warning(f"Failed to rename hidden key file '{old_key_file}' to '{new_key_file}': {e}")
                # Continue without raising the exception

def main(encrypted_dir, decrypted_dir, public_key_path, private_key_path=None, debug=False):
    if not os.path.exists(encrypted_dir):
        print(f"Encrypted directory '{encrypted_dir}' does not exist.")
        sys.exit(1)
    if not os.path.exists(decrypted_dir):
        print(f"Decrypted directory '{decrypted_dir}' does not exist.")
        sys.exit(1)

    FUSE(
        EncryptedFS(encrypted_dir, decrypted_dir, public_key_path, private_key_path, debug),
        decrypted_dir,
        foreground=True
    )

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Encrypted FUSE filesystem.')
    parser.add_argument('encrypted', help='Directory to store encrypted files')
    parser.add_argument('decrypted', help='Mount point for decrypted access to files')
    parser.add_argument('public_key', help='Path to public key for encryption')
    parser.add_argument('--private_key', help='Path to private key for decryption')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode to print symmetric keys')
    args = parser.parse_args()

    if not os.path.exists(args.public_key):
        print("Public key not found.")
        sys.exit(1)

    if args.private_key and not os.path.exists(args.private_key):
        print("Private key not found.")
        sys.exit(1)

    main(
        encrypted_dir=args.encrypted,
        decrypted_dir=args.decrypted,
        public_key_path=args.public_key,
        private_key_path=args.private_key,
        debug=args.debug
    )
