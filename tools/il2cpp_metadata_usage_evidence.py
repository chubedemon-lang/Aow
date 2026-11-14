"""Decode IL2CPP metadata-usage MethodDef tokens from offline evidence.

The helpers do not inspect an APK or infer runtime object layouts. They only
decode the versioned encoded-index representation after a caller has obtained
a bounded token from an authorized offline analysis pass.
"""

_METHOD_DEF_USAGE = 3
_USAGE_MASK = 0xE0000000
_INDEX_MASK = 0x1FFFFFFF
_MAX_U32 = 0xFFFFFFFF


def decode_method_def_usage_index(encoded, metadata_version):
    """Return the MethodDef table index, or None for another/unresolved token.

    For metadata v27 and later, the low bit marks an unresolved metadata-usage
    token and the remaining index bits are shifted right by one.
    """
    if type(encoded) is not int or not 0 <= encoded <= _MAX_U32:
        raise ValueError("encoded metadata usage must be an unsigned 32-bit integer")
    if type(metadata_version) is not int or metadata_version < 1:
        raise ValueError("metadata_version must be a positive integer")
    usage_type = (encoded & _USAGE_MASK) >> 29
    if usage_type != _METHOD_DEF_USAGE:
        return None
    raw_index = encoded & _INDEX_MASK
    if metadata_version >= 27:
        if not raw_index & 1:
            return None
        return raw_index >> 1
    return raw_index


def encode_method_def_usage_index(method_index, metadata_version):
    """Encode a MethodDef index using the metadata version's usage marker."""
    if type(method_index) is not int or method_index < 0:
        raise ValueError("method_index must be a non-negative integer")
    if type(metadata_version) is not int or metadata_version < 1:
        raise ValueError("metadata_version must be a positive integer")
    if metadata_version >= 27:
        if method_index > (_INDEX_MASK >> 1):
            raise ValueError("method_index does not fit the v27+ usage encoding")
        raw_index = (method_index << 1) | 1
    else:
        if method_index > _INDEX_MASK:
            raise ValueError("method_index does not fit the encoded usage index")
        raw_index = method_index
    return (_METHOD_DEF_USAGE << 29) | raw_index
