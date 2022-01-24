import base64
import math
import secrets
import argon2

RANDOM_STRING_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
UNUSABLE_PASSWORD_PREFIX = '!'  # This will never be a valid encoded hash
UNUSABLE_PASSWORD_SUFFIX_LENGTH = 40  # number of random chars to add after UNUSABLE_PASSWORD_PREFIX


def get_random_string(length, allowed_chars=RANDOM_STRING_CHARS):
    """
    Return a securely generated random string.
    The bit length of the returned value can be calculated with the formula:
        log_2(len(allowed_chars)^length)
    For example, with default `allowed_chars` (26+26+10), this gives:
      * length: 12, bit length =~ 71 bits
      * length: 22, bit length =~ 131 bits
    """
    return ''.join(secrets.choice(allowed_chars) for i in range(length))


def mask_hash(hash, show=6, char="*"):
    """
    Return the given hash, with only the first ``show`` number shown. The
    rest are masked with ``char`` for security reasons.
    """
    masked = hash[:show]
    masked += char * len(hash[show:])
    return masked


def must_update_salt(salt, expected_entropy):
    # Each character in the salt provides log_2(len(alphabet)) bits of entropy.
    return len(salt) * math.log2(len(RANDOM_STRING_CHARS)) < expected_entropy


def is_password_usable(encoded):
    """
    Return True if this password wasn't generated as an unusable password
    """
    return encoded is None or not encoded.startswith(UNUSABLE_PASSWORD_PREFIX)

def make_password(password, salt=None):
    """
    Turn a plain-text password into a hash for database storage
    Same as encode() but generate a new random salt. If password is None then
    return a concatenation of UNUSABLE_PASSWORD_PREFIX and a random string,
    which disallows logins. Additional random string reduces chances of gaining
    access to staff or superuser accounts.
    """
    if password is None:
        return UNUSABLE_PASSWORD_PREFIX + get_random_string(UNUSABLE_PASSWORD_SUFFIX_LENGTH)
    if not isinstance(password, (bytes, str)):
        raise TypeError(
            'Password must be a string or bytes, got %s.'
            % type(password).__qualname__
        )

    salt = salt or Argon2PasswordHasher.salt()
    return Argon2PasswordHasher.encode(password, salt)


def check_password(password, encoded):
    """
    Return a boolean of whether the raw password matches the three
    part encoded digest.
    """
    if password is None or not is_password_usable(encoded):
        return False

    is_correct = Argon2PasswordHasher.verify(password, encoded)
    return is_correct

class Argon2PasswordHasher:
    """
    Helper for using the argon2 algorithm.
    Implementation of Django Argon2PasswordHasher.
    """
    algorithm = 'argon2'

    time_cost = 2
    memory_cost = 102400
    parallelism = 8
    salt_entropy = 128

    @classmethod
    def encode(cls, password, salt):
        params = cls.params()
        data = argon2.low_level.hash_secret(
            password.encode(),
            salt.encode(),
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=params.type,
        )
        return cls.algorithm + data.decode('ascii')

    @classmethod
    def decode(cls, encoded):
        algorithm, rest = encoded.split('$', 1)
        assert algorithm == cls.algorithm
        params = argon2.extract_parameters('$' + rest)
        variety, *_, b64salt, hash = rest.split('$')
        # Add padding.
        b64salt += '=' * (-len(b64salt) % 4)
        salt = base64.b64decode(b64salt).decode('latin1')
        return {
            'algorithm': algorithm,
            'hash': hash,
            'memory_cost': params.memory_cost,
            'parallelism': params.parallelism,
            'salt': salt,
            'time_cost': params.time_cost,
            'variety': variety,
            'version': params.version,
            'params': params,
        }

    @classmethod
    def verify(cls, password, encoded):
        algorithm, rest = encoded.split('$', 1)
        assert algorithm == cls.algorithm
        try:
            return argon2.PasswordHasher().verify('$' + rest, password)
        except argon2.exceptions.VerificationError:
            return False

    @classmethod
    def safe_summary(cls, encoded):
        decoded = cls.decode(encoded)
        return {
            'algorithm': decoded['algorithm'],
            'variety': decoded['variety'],
            'version': decoded['version'],
            'memory cost': decoded['memory_cost'],
            'time cost': decoded['time_cost'],
            'parallelism': decoded['parallelism'],
            'salt': mask_hash(decoded['salt']),
            'hash': mask_hash(decoded['hash']),
        }

    @classmethod
    def must_update(cls, encoded):
        decoded = cls.decode(encoded)
        current_params = decoded['params']
        new_params = cls.params()
        # Set salt_len to the salt_len of the current parameters because salt
        # is explicitly passed to argon2.
        new_params.salt_len = current_params.salt_len
        update_salt = must_update_salt(decoded['salt'], cls.salt_entropy)
        return (current_params != new_params) or update_salt

    @classmethod
    def harden_runtime(cls, password, encoded):
        # The runtime for Argon2 is too complicated to implement a sensible
        # hardening algorithm.
        pass

    @classmethod
    def params(cls):
        # salt_len is a noop, because we provide our own salt.
        return argon2.Parameters(
            type=argon2.low_level.Type.ID,
            version=argon2.low_level.ARGON2_VERSION,
            salt_len=argon2.DEFAULT_RANDOM_SALT_LENGTH,
            hash_len=argon2.DEFAULT_HASH_LENGTH,
            time_cost=cls.time_cost,
            memory_cost=cls.memory_cost,
            parallelism=cls.parallelism,
        )

    @classmethod
    def salt(cls):
        """
        Generate a cryptographically secure nonce salt in ASCII with an entropy
        of at least `salt_entropy` bits.
        """
        # Each character in the salt provides
        # log_2(len(alphabet)) bits of entropy.
        char_count = math.ceil(cls.salt_entropy / math.log2(len(RANDOM_STRING_CHARS)))
        return get_random_string(char_count, allowed_chars=RANDOM_STRING_CHARS)