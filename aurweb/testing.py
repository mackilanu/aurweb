from aurweb.db import get_engine


def setup_test_db(*args):
    """ This function will wipe out target tables, given via *args. """
    engine = get_engine()
    conn = engine.connect()

    tables = list(args)
    for table in tables:
        conn.execute(f"DELETE FROM {table}")
    conn.close()
