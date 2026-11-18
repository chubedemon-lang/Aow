"""Decode versioned IL2CPP metadata-usage tokens from offline evidence.

The helpers do not inspect an APK or infer runtime object layouts. They only
decode a bounded token after a caller has obtained it from an authorized
offline analysis pass. A decoded FieldInfo usage index is not, by itself, a
managed field name or a metadata FieldDefinition index.
"""

_METHOD_DEF_USAGE = 3
_FIELD_INFO_USAGE = 4
_USAGE_MASK = 0xE0000000
_INDEX_MASK = 0x1FFFFFFF
_MAX_U32 = 0xFFFFFFFF


def _validate_token_and_version(encoded, metadata_version):
    if type(encoded) is not int or not 0 <= encoded <= _MAX_U32:
        raise ValueError("encoded metadata usage must be an unsigned 32-bit integer")
    if type(metadata_version) is not int or metadata_version < 1:
        raise ValueError("metadata_version must be a positive integer")


def _decode_usage_index(encoded, metadata_version, expected_usage_type):
    _validate_token_and_version(encoded, metadata_version)
    usage_type = (encoded & _USAGE_MASK) >> 29
    if usage_type != expected_usage_type:
        return None
    raw_index = encoded & _INDEX_MASK
    if metadata_version >= 27:
        # In v27+, an even low index bit denotes an unresolved token. Do not
        # promote its shifted payload to a resolved table index.
        if not raw_index & 1:
            return None
        return raw_index >> 1
    return raw_index


def _encode_usage_index(index, metadata_version, usage_type, label):
    if type(index) is not int or index < 0:
        raise ValueError(label + " must be a non-negative integer")
    if type(metadata_version) is not int or metadata_version < 1:
        raise ValueError("metadata_version must be a positive integer")
    if metadata_version >= 27:
        if index > (_INDEX_MASK >> 1):
            raise ValueError(label + " does not fit the v27+ usage encoding")
        raw_index = (index << 1) | 1
    else:
        if index > _INDEX_MASK:
            raise ValueError(label + " does not fit the encoded usage index")
        raw_index = index
    return (usage_type << 29) | raw_index


def decode_method_def_usage_index(encoded, metadata_version):
    """Return the MethodDef usage index, or None for another/unresolved token."""
    return _decode_usage_index(encoded, metadata_version, _METHOD_DEF_USAGE)


def encode_method_def_usage_index(method_index, metadata_version):
    """Encode a MethodDef usage index using the metadata version's marker."""
    return _encode_usage_index(
        method_index, metadata_version, _METHOD_DEF_USAGE, "method_index"
    )


def decode_field_info_usage_index(encoded, metadata_version):
    """Return a resolved FieldInfo usage index, or None for another/unresolved token.

    The returned value is the index carried by a FieldInfo metadata-usage
    token. It must not be treated as a FieldDefinition index until the
    corresponding metadata FieldRef table entry has been validated.
    """
    return _decode_usage_index(encoded, metadata_version, _FIELD_INFO_USAGE)


def encode_field_info_usage_index(field_info_index, metadata_version):
    """Encode a FieldInfo usage index with the version-specific marker."""
    return _encode_usage_index(
        field_info_index, metadata_version, _FIELD_INFO_USAGE, "field_info_index"
    )
