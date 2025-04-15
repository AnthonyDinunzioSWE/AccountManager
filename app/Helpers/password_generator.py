from werkzeug.security import generate_password_hash, check_password_hash

def password_generator(length, char_set, exclude_similar):
    """
    Generates a random password based on the specified length, character set, and whether to exclude similar characters.
    
    :param length: Length of the password to be generated.
    :param char_set: Character set to use for generating the password.
    :param exclude_similar: Boolean indicating whether to exclude similar characters.
    :return: Generated password as a string.
    """
    import random
    import string

    if exclude_similar:
        char_set = char_set.replace('l', '').replace('I', '').replace('1', '').replace('O', '').replace('0', '')
    
    return ''.join(random.choice(char_set) for _ in range(length))


def hash_password(password):
    """
    Hashes the given password using a secure hashing algorithm.
    
    :param password: Password to be hashed.
    :return: Hashed password as a string.
    """
    return generate_password_hash(password)


def unhash_password(hashed_password, password):
    """
    Compares a hashed password with a plain text password.
    
    :param hashed_password: Hashed password to compare against.
    :param password: Plain text password to compare.
    :return: Boolean indicating whether the passwords match.
    """
    return check_password_hash(hashed_password, password)