def columns(table_name, db_type, user_id):
    if db_type == "mysql":
        # ruleid: kscan-fstring-sql
        query = f"DESCRIBE {table_name}"
    elif db_type == "postgresql":
        # ruleid: kscan-fstring-sql
        query = f"""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = '{table_name}'
        """
    # ruleid: kscan-fstring-sql
    q2 = "SELECT * FROM users WHERE id = {}".format(user_id)
    # ruleid: kscan-fstring-sql
    q3 = "DELETE FROM sessions WHERE user_id = %s" % user_id
    # ok: kscan-fstring-sql
    q4 = "SELECT * FROM users WHERE id = %s"
    # ok: kscan-fstring-sql
    msg = f"Hello {user_id}, welcome"
    return query, q2, q3, q4, msg
