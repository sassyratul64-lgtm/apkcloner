import pytest
from core.modifier import validate_package_id, InvalidPackageId


@pytest.mark.parametrize("pkg", [
    "com.ratul.myapp",
    "com.example.app123",
    "org.fdroid.fdroid",
    "a.b",
])
def test_valid_package_ids_accepted(pkg):
    validate_package_id(pkg)  # should not raise


@pytest.mark.parametrize("pkg", [
    "com",                      # single segment
    "123com.example",           # leading digit
    "com..example",             # empty segment
    "com.example.class",        # reserved keyword
    "com example.app",          # space
    "com.example.app!",         # invalid char
    "",
])
def test_invalid_package_ids_rejected(pkg):
    with pytest.raises(InvalidPackageId):
        validate_package_id(pkg)
