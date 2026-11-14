import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { beforeEach } from 'vitest';

beforeEach(() => {
  // Every test starts with an empty IndexedDB.
  globalThis.indexedDB = new IDBFactory();
});
