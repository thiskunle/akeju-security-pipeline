# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Security Pipeline, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
# Deliberately insecure sample. The self-test proves the pipeline catches this. Never deploy it.
import subprocess
import sqlite3

import flask
from flask import request

app = flask.Flask(__name__)


@app.route("/run")
def run():
    return subprocess.check_output(request.args["cmd"], shell=True)


@app.route("/user")
def user():
    connection = sqlite3.connect("app.db")
    return str(connection.execute("SELECT * FROM users WHERE name = '" + request.args["name"] + "'").fetchall())


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
