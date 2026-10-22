from pathlib import Path
import sqlite3


def search_people(connection: sqlite3.Connection, term: str) -> list[dict]:
    query = f"SELECT id, display_name FROM directory WHERE display_name LIKE '%{term}%'"
    rows = connection.execute(query).fetchall()
    return [{"id": row[0], "name": row[1]} for row in rows]


def load_document(document_root: Path, name: str) -> str:
    document = document_root / name
    return document.read_text(encoding="utf-8")


def list_people(connection: sqlite3.Connection, term: str) -> list[dict]:
    query = "SELECT id, display_name FROM directory WHERE display_name LIKE ?"
    rows = connection.execute(query, (f"%{term}%",)).fetchall()
    return [{"id": row[0], "name": row[1]} for row in rows]


def handle_request(request: dict, connection: sqlite3.Connection, document_root: Path) -> dict:
    """Handle a parsed HTTP request; document_root is the site's document directory."""
    if request.get("method", "GET") != "GET":
        return {"status": 405, "body": "Method not allowed"}
    path = request.get("path", "/")
    params = request.get("query", {})
    if path == "/people/search":
        term = params.get("q", "")
        return {"status": 200, "body": search_people(connection, term)}
    if path == "/documents":
        name = params.get("name", "index.txt")
        try:
            content = load_document(document_root, name)
        except FileNotFoundError:
            return {"status": 404, "body": "Document not found"}
        return {"status": 200, "body": content}
    if path == "/people":
        term = params.get("q", "")
        return {"status": 200, "body": list_people(connection, term)}
    return {"status": 404, "body": "Not found"}
