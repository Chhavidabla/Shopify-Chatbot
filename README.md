# Shopify-Chatbot
# 🤖 Shopify Chatbot – AI-Powered E-commerce Assistant

A smart, interactive chatbot built using Flask (backend) and HTML/CSS/JS (frontend) that helps users explore and search e-commerce products like laptops, clothing, books, and more.


## 🧩 Features

- 🔐 User login + JWT-based authentication
- 💬 Conversational chatbot UI with product filtering
- 🛍️ Categories: electronics, clothing, books, home, sports
- 📊 Real-time chat history, session duration & product suggestions
- 💡 Handles natural queries like "show me laptops under $1000"
- 🧠 Intent recognition + dynamic response generation

---

## 🛠️ Tech Stack

| Frontend        | Backend          | Database     |
|-----------------|------------------|--------------|
| HTML, CSS, JS   | Flask (Python)   | SQLite (via SQLAlchemy) |

Extras:
- JWT for auth
- SQLAlchemy ORM
- Flask-CORS
- Bootstrap + responsive design
- Faker/mock products

---

## 🚀 Getting Started

### 1. Clone Repo & Setup Backend

```bash
git clone https://github.com/Chhavidabla/shopify-chatbot.git
cd shopify-chatbot
pip install -r requirements.txt
python app.py
