from wiguard.services.storage import Storage


def test_storage_atomic_save_and_backup(tmp_path):
    path = tmp_path / "state.json"
    storage = Storage(path)
    storage.save({"version": 1})
    storage.save({"version": 2})
    assert storage.load()["version"] == 2
    assert storage.backup_path.exists()
