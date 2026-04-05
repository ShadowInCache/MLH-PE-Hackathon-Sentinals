import os

from app import create_app

app = create_app()


def _is_truthy(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", 5000)),
        debug=_is_truthy(os.environ.get("FLASK_DEBUG", "0")),
    )
