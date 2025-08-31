from flask import Flask, render_template, request, jsonify
from app.api import lookup_threat
from app.db import threats

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("dashboard.html")

@app.route("/lookup", methods=["POST"])
def lookup():
    data = request.json
    result = lookup_threat(data["query"])
    threats.insert_one(result)
    return jsonify(result)
