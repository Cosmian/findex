# -*- coding: utf-8 -*-
import unittest
from cosmian_findex import IndexedValue, Label, MasterKey, InternalFindex
from typing import Dict, List, Set, Tuple


class TestStructures(unittest.TestCase):
    def test_indexed_value_location(self) -> None:
        bytes = b'location uid'
        iv = IndexedValue.from_location(bytes)
        self.assertIsInstance(iv, IndexedValue)
        self.assertEqual(iv.get_location(), bytes)

        # Cannot access keyword from a location
        self.assertIsNone(iv.get_keyword())

    def test_indexed_value_keyword(self) -> None:
        bytes = b'example keyword'
        iv = IndexedValue.from_keyword(bytes)
        self.assertIsInstance(iv, IndexedValue)
        self.assertEqual(iv.get_keyword(), bytes)

        # Cannot access location from a keyword
        self.assertIsNone(iv.get_location())

        # Check comparison
        word1 = IndexedValue.from_keyword(b'word1')
        word1_bis = IndexedValue.from_keyword(b'word1')
        word2 = IndexedValue.from_keyword(b'word2')

        self.assertEqual(hash(word1), hash(word1_bis))
        self.assertEqual(word1, word1_bis)

        self.assertNotEqual(hash(word1), hash(word2))
        self.assertNotEqual(word1, word2)

    def test_label(self) -> None:
        rand_label = Label.random()
        self.assertIsInstance(rand_label, Label)

        saved_bytes = rand_label.to_bytes()
        reloaded_label = Label.from_bytes(saved_bytes)
        self.assertEqual(saved_bytes, reloaded_label.to_bytes())

    def test_masterkeys(self) -> None:
        msk = MasterKey.random()
        self.assertIsInstance(msk, MasterKey)

        saved_bytes = msk.to_bytes()
        reloaded_msk = MasterKey.from_bytes(saved_bytes)
        self.assertEqual(saved_bytes, reloaded_msk.to_bytes())

        with self.assertRaises(ValueError):
            MasterKey.from_bytes(b'wrong size')


class FindexHashmap:
    """Implement Findex callbacks using hashmaps"""

    def __init__(self, db: Dict[bytes, List[str]]):
        self.db = db
        self.entry_table: Dict[bytes, bytes] = {}
        self.chain_table: Dict[bytes, bytes] = {}

    # Create callback functions
    def fetch_entry(self, uids: List[bytes]) -> Dict[bytes, bytes]:
        """DB request to fetch entry_table elements"""
        res = {}
        for uid in uids:
            if uid in self.entry_table:
                res[uid] = self.entry_table[uid]
        return res

    def fetch_all_entry_table_uids(self) -> Set[bytes]:
        return set(self.entry_table.keys())

    def fetch_chain(self, uids: List[bytes]) -> Dict[bytes, bytes]:
        """DB request to fetch chain_table elements"""
        res = {}
        for uid in uids:
            if uid in self.chain_table:
                res[uid] = self.chain_table[uid]
        return res

    def upsert_entry(
        self, entries: Dict[bytes, Tuple[bytes, bytes]]
    ) -> Dict[bytes, bytes]:
        """DB request to upsert entry_table elements.
        WARNING: This implementation will not work with concurrency.
        """
        rejected_lines = {}
        for uid, (old_val, new_val) in entries.items():
            if uid in self.entry_table:
                if self.entry_table[uid] == old_val:
                    self.entry_table[uid] = new_val
                else:
                    rejected_lines[uid] = self.entry_table[uid]
            elif not old_val:
                self.entry_table[uid] = new_val
            else:
                raise Exception('Line got deleted in Entry Table')

        return rejected_lines

    def insert_entry(self, entries: Dict[bytes, bytes]) -> None:
        """DB request to insert entry_table elements"""
        for uid in entries:
            if uid in self.entry_table:
                raise KeyError('Conflict in Entry Table for UID: {uid}')
            self.entry_table[uid] = entries[uid]

    def insert_chain(self, entries: Dict[bytes, bytes]) -> None:
        """DB request to insert chain_table elements"""
        for uid in entries:
            if uid in self.chain_table:
                raise KeyError('Conflict in Chain Table for UID: {uid}')
            self.chain_table[uid] = entries[uid]

    def list_removed_locations(self, uids: List[bytes]) -> List[bytes]:
        res = []
        for uid in uids:
            if not uid in self.db:
                res.append(uid)
        return res

    def update_lines(
        self,
        removed_chain_table_uids: List[bytes],
        new_encrypted_entry_table_items: Dict[bytes, bytes],
        new_encrypted_chain_table_items: Dict[bytes, bytes],
    ) -> None:
        # remove all entries from entry table
        self.entry_table.clear()

        # remove entries from chain table
        for uid in removed_chain_table_uids:
            del self.chain_table[uid]

        # insert new chains
        self.insert_chain(new_encrypted_chain_table_items)

        # insert newly encrypted entries
        self.insert_entry(new_encrypted_entry_table_items)


class TestFindex(unittest.TestCase):
    def setUp(self) -> None:
        # Create structures needed by Findex
        self.msk = MasterKey.random()
        self.label = Label.random()

        self.db = {
            b'1': ['Martin', 'Sheperd'],
            b'2': ['Martial', 'Wilkins'],
            b'3': ['John', 'Sheperd'],
        }

        self.findex_backend = FindexHashmap(self.db)
        self.findex_interface = InternalFindex()

    def test_upsert_search(self) -> None:
        indexed_values_and_keywords = {
            IndexedValue.from_location(k): v for k, v in self.db.items()
        }

        # Calling Upsert without setting the proper callbacks will raise an Exception
        with self.assertRaises(Exception):
            self.findex_interface.upsert_wrapper(
                indexed_values_and_keywords, self.msk, self.label
            )

        # Set upsert callbacks here
        self.findex_interface.set_upsert_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.upsert_entry,
            self.findex_backend.insert_chain,
        )

        self.findex_interface.upsert_wrapper(
            indexed_values_and_keywords, self.msk, self.label
        )
        self.assertEqual(len(self.findex_backend.entry_table), 5)
        self.assertEqual(len(self.findex_backend.chain_table), 5)

        # Set search callbacks here
        self.findex_interface.set_search_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.fetch_chain,
        )

        res = self.findex_interface.search_wrapper(['Martial'], self.msk, self.label)
        self.assertEqual(len(res), 1)
        self.assertEqual(len(res['Martial']), 1)
        self.assertEqual(res['Martial'][0], b'2')

        res = self.findex_interface.search_wrapper(
            ['Sheperd', 'Wilkins'], self.msk, self.label
        )
        self.assertEqual(len(res['Sheperd']), 2)
        self.assertEqual(len(res['Wilkins']), 1)

    def test_graph_upsert_search(self) -> None:
        self.findex_interface.set_upsert_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.upsert_entry,
            self.findex_backend.insert_chain,
        )
        self.findex_interface.set_search_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.fetch_chain,
        )

        indexed_values_and_keywords = {
            IndexedValue.from_location(k): v for k, v in self.db.items()
        }
        self.findex_interface.upsert_wrapper(
            indexed_values_and_keywords, self.msk, self.label
        )

        # Adding custom keywords graph
        graph = {
            IndexedValue.from_keyword(b'Mart'): ['Mar'],
            IndexedValue.from_keyword(b'Marti'): ['Mart'],
            IndexedValue.from_keyword(b'Martin'): ['Marti'],
            IndexedValue.from_keyword(b'Martia'): ['Marti'],
            IndexedValue.from_keyword(b'Martial'): ['Martia'],
        }
        self.findex_interface.upsert_wrapper(graph, self.msk, self.label)

        self.assertEqual(len(self.findex_backend.entry_table), 9)
        self.assertEqual(len(self.findex_backend.chain_table), 9)

        res = self.findex_interface.search_wrapper(['Mar'], self.msk, self.label)
        # 2 names starting with Mar
        self.assertEqual(len(res['Mar']), 2)

        # Test progress callback
        def false_progress_callback(res: Dict[str, List[IndexedValue]]):
            self.assertEqual(len(res['Mar']), 1)
            return False

        res = self.findex_interface.search_wrapper(
            ['Mar'], self.msk, self.label, progress_callback=false_progress_callback
        )
        # no locations returned since the progress_callback stopped the recursion
        self.assertEqual(len(res['Mar']), 0)

        def early_stop_progress_callback(res: Dict[str, List[IndexedValue]]):
            if 'Martin' in res:
                return False
            return True

        res = self.findex_interface.search_wrapper(
            ['Mar'],
            self.msk,
            self.label,
            progress_callback=early_stop_progress_callback,
        )
        # only one location found after early stopping
        self.assertEqual(len(res['Mar']), 1)

    def test_compact(self) -> None:
        # use upsert, search and compact callbacks
        self.findex_interface.set_upsert_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.upsert_entry,
            self.findex_backend.insert_chain,
        )
        self.findex_interface.set_search_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.fetch_chain,
        )
        self.findex_interface.set_compact_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.fetch_chain,
            self.findex_backend.update_lines,
            self.findex_backend.list_removed_locations,
            self.findex_backend.fetch_all_entry_table_uids,
        )

        indexed_values_and_keywords = {
            IndexedValue.from_location(k): v for k, v in self.db.items()
        }
        self.findex_interface.upsert_wrapper(
            indexed_values_and_keywords, self.msk, self.label
        )

        new_label = Label.random()
        res = self.findex_interface.search_wrapper(['Sheperd'], self.msk, new_label)
        # new_label cannot search before compacting
        self.assertEqual(len(res), 0)

        # removing 2nd db line
        del self.db[b'2']
        self.findex_interface.compact_wrapper(1, self.msk, self.msk, new_label)

        # now new_label can perform search
        res = self.findex_interface.search_wrapper(['Sheperd'], self.msk, new_label)
        self.assertEqual(len(res['Sheperd']), 2)
        # but not the previous label
        res = self.findex_interface.search_wrapper(['Sheperd'], self.msk, self.label)
        self.assertEqual(len(res), 0)

        # and the keywords corresponding to the 2nd line have been removed
        res = self.findex_interface.search_wrapper(
            ['Martial', 'Wilkins'], self.msk, new_label
        )
        assert 'Martial' not in res
        assert 'Wilkins' not in res


if __name__ == '__main__':
    unittest.main()
