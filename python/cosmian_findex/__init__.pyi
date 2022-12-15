from typing import Callable, Optional, Dict, List

class IndexedValue:
    """The value indexed by a `Keyword`. It can be either a `Location` or another
    `Keyword` in case the searched `Keyword` was a tree node.
    """

    def is_location(self) -> bool:
        """Checks whether the `IndexedValue` is a location.

        Returns:
            bool
        """
    def is_keyword(self) -> bool:
        """Checks whether the `IndexedValue` is a keyword.

        Returns:
            bool
        """
    def get_location(self) -> Optional[bytes]:
        """Returns the underlying location if the `IndexedValue` is one.

        Returns:
            Optional[bytes]
        """
    def get_keyword(self) -> Optional[bytes]:
        """Returns the underlying keyword if the `IndexedValue` is one.

        Returns:
            Optional[bytes]
        """
    @staticmethod
    def from_location(location_bytes: bytes) -> IndexedValue:
        """Create `IndexedValue` from a location in bytes.

        Args:
            location_bytes (bytes)

        Returns:
            IndexedValue
        """
    @staticmethod
    def from_keyword(keyword_bytes: bytes) -> IndexedValue:
        """Create `IndexedValue` from a keyword in bytes.

        Args:
            keyword_bytes (bytes)

        Returns:
            IndexedValue
        """

class Label:
    """Additional data used to encrypt the entry table."""

    def to_bytes(self) -> bytes:
        """Convert to bytes.

        Returns:
            bytes
        """
    @staticmethod
    def random() -> Label:
        """Initialize a random label.

        Returns:
            Label
        """
    @staticmethod
    def from_bytes(label_bytes: bytes) -> Label:
        """Load from bytes.

        Args:
            label_bytes (bytes)

        Returns:
            Label
        """

class MasterKey:
    """Input key used to derive Findex keys."""

    def to_bytes(self) -> bytes:
        """Convert to bytes.

        Returns:
            bytes
        """
    @staticmethod
    def random() -> MasterKey:
        """Initialize a random key.

        Returns:
            MasterKey
        """
    @staticmethod
    def from_bytes(key_bytes: bytes) -> MasterKey:
        """Load from bytes.

        Args:
            key_bytes (bytes)

        Returns:
            MasterKey
        """

class InternalFindex:
    """This is an internal class. See `cloudproof_py.findex.Findex` abstract class instead."""

    def __init__(
        self,
        fetch_entry: Callable,
        fetch_chain: Callable,
        upsert_entry: Callable,
        upsert_chain: Callable,
        update_lines: Callable,
        list_removed_locations: Callable,
        progress_callback: Callable,
    ): ...
    def upsert_wrapper(
        self,
        indexed_values_and_keywords: Dict[IndexedValue, List[str]],
        master_key: MasterKey,
        label: Label,
    ): ...
    def search_wrapper(
        self,
        keywords: List[str],
        msk: MasterKey,
        label: Label,
        max_result_per_keyword: int = 2**32 - 1,
        max_depth: int = 100,
    ): ...
    def compact_wrapper(
        self,
        num_reindexing_before_full_set: int,
        master_key: MasterKey,
        new_master_key: MasterKey,
        new_label: Label,
    ): ...
