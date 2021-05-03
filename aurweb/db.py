import math

import aurweb.config
import aurweb.util

# Global engine object initialized by get_engine().
engine = None

# ORM Session class initialized by get_engine().
Session = None

# Global ORM Session object initialized by get_engine().
session = None

# Global introspected object memo.
_introspected = dict()


def make_random_value(table, column):
    global _introspected

    # If the target column is not yet introspected, store its introspection
    # object into our global `introspected` memo.
    if str(column) not in _introspected:
        from sqlalchemy import inspect
        target_column = str(column).split('.')[-1]
        col = list(filter(lambda c: c.name == target_column,
                          inspect(table).columns))[0]
        _introspected[str(column)] = col

    col = _introspected.get(str(column))
    length = col.type.length

    string = aurweb.util.make_random_string(length)
    while session.query(table).filter(column == string).first():
        string = aurweb.util.make_random_string(length)
    return string


def query(model, *args, **kwargs):
    return session.query(model).filter(*args, **kwargs)


def create(model, *args, **kwargs):
    instance = model(*args, **kwargs)
    session.add(instance)
    session.commit()
    return instance


def delete(model, *args, **kwargs):
    instance = session.query(model).filter(*args, **kwargs)
    for record in instance:
        session.delete(record)
    session.commit()


def get_sqlalchemy_url():
    """
    Build an SQLAlchemy for use with create_engine based on the aurweb configuration.
    """
    import sqlalchemy
    aur_db_backend = aurweb.config.get('database', 'backend')
    if aur_db_backend == 'mysql':
        return sqlalchemy.engine.url.URL(
            'mysql+mysqlconnector',
            username=aurweb.config.get('database', 'user'),
            password=aurweb.config.get('database', 'password'),
            host=aurweb.config.get('database', 'host'),
            database=aurweb.config.get('database', 'name')
        )
    elif aur_db_backend == 'sqlite':
        return sqlalchemy.engine.url.URL(
            'sqlite',
            database=aurweb.config.get('database', 'name'),
        )
    else:
        raise ValueError('unsupported database backend')


def get_engine():
    """
    Return the global SQLAlchemy engine.

    The engine is created on the first call to get_engine and then stored in the
    `engine` global variable for the next calls.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    global engine, session, Session

    if engine is None:
        engine = create_engine(get_sqlalchemy_url(),
                # check_same_thread is for a SQLite technicality
                # https://fastapi.tiangolo.com/tutorial/sql-databases/#note
                connect_args={"check_same_thread": False})
        Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        session = Session()

    return engine


def connect():
    """
    Return an SQLAlchemy connection. Connections are usually pooled. See
    <https://docs.sqlalchemy.org/en/13/core/connections.html>.

    Since SQLAlchemy connections are context managers too, you should use it
    with Python’s `with` operator, or with FastAPI’s dependency injection.
    """
    return get_engine().connect()


class ConnectionExecutor:
    _conn = None
    _paramstyle = None

    def __init__(self, conn, backend=aurweb.config.get("database", "backend")):
        self._conn = conn
        if backend == "mysql":
            import mysql.connector
            self._paramstyle = mysql.connector.paramstyle
        elif backend == "sqlite":
            import sqlite3
            self._paramstyle = sqlite3.paramstyle

    def paramstyle(self):
        return self._paramstyle

    def execute(self, query, params=()):
        if self._paramstyle in ('format', 'pyformat'):
            query = query.replace('%', '%%').replace('?', '%s')
        elif self._paramstyle == 'qmark':
            pass
        else:
            raise ValueError('unsupported paramstyle')

        cur = self._conn.cursor()
        cur.execute(query, params)

        return cur

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


class Connection:
    _executor = None
    _conn = None

    def __init__(self):
        aur_db_backend = aurweb.config.get('database', 'backend')

        if aur_db_backend == 'mysql':
            import mysql.connector
            aur_db_host = aurweb.config.get('database', 'host')
            aur_db_name = aurweb.config.get('database', 'name')
            aur_db_user = aurweb.config.get('database', 'user')
            aur_db_pass = aurweb.config.get('database', 'password')
            aur_db_socket = aurweb.config.get('database', 'socket')
            self._conn = mysql.connector.connect(host=aur_db_host,
                                                 user=aur_db_user,
                                                 passwd=aur_db_pass,
                                                 db=aur_db_name,
                                                 unix_socket=aur_db_socket,
                                                 buffered=True)
        elif aur_db_backend == 'sqlite':
            import sqlite3
            aur_db_name = aurweb.config.get('database', 'name')
            self._conn = sqlite3.connect(aur_db_name)
            self._conn.create_function("POWER", 2, math.pow)
        else:
            raise ValueError('unsupported database backend')

        self._conn = ConnectionExecutor(self._conn)

    def execute(self, query, params=()):
        return self._conn.execute(query, params)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()
