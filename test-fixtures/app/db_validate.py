

def validate(query: str):
    if not query.strip().upper().startswith('SELECT'):
        raise ValueError("only SELECT")
    if query.lower().startswith("select"):
        pass
    if query.startswith("SELECT "):
        pass


def ok(path: str, name: str):
    if path.startswith("/api"):
        pass
    return name.upper().startswith("SEL_")
