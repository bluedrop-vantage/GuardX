from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from guardx_control.config import get_settings
from guardx_control.db import Base
import guardx_control.models  # noqa: F401  (register all mappers)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Do NOT push the URL through config.set_main_option — ConfigParser interpolates
# '%' chars (e.g. '%40' in URL-encoded passwords) and errors out. We build the
# engine directly from the resolved URL instead.
DB_URL = get_settings().database_url
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=DB_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(DB_URL, poolclass=pool.NullPool, future=True)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
