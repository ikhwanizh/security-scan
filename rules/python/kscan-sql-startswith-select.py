

def validate(query: str):
    # ruleid: kscan-sql-startswith-select
    if not query.strip().upper().startswith('SELECT'):
        raise ValueError("only SELECT")
    # ruleid: kscan-sql-startswith-select
    if query.lower().startswith("select"):
        pass
    # ruleid: kscan-sql-startswith-select
    if query.startswith("SELECT "):
        pass


def ok(path: str, name: str):
    # ok: kscan-sql-startswith-select
    if path.startswith("/api"):
        pass
    # ok: kscan-sql-startswith-select
    return name.upper().startswith("SEL_")
