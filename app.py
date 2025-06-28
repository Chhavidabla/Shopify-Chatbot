# app.py - Main Flask Application
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import os
import logging
from functools import wraps
import re
import random

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ecommerce_chatbot.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-string')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['CORS_HEADERS'] = 'Content-Type'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
#CORS(app, origins=['http://localhost:3000', 'http://127.0.0.1:5500'])  # Allow frontend origins
CORS(app, resources={r"/api/*": {"origins": ["http://127.0.0.1:5500", "http://127.0.0.1:3002"]}})

 

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========================= DATABASE MODELS =========================

class User(db.Model):
    """User model for authentication and session management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    chat_sessions = db.relationship('ChatSession', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Product(db.Model):
    """Product model for e-commerce inventory"""
    __tablename__ = 'products'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False, index=True)
    category = db.Column(db.String(100), nullable=False, index=True)
    brand = db.Column(db.String(100))
    stock_quantity = db.Column(db.Integer, default=0)
    sku = db.Column(db.String(50), unique=True)
    image_url = db.Column(db.String(500))
    rating = db.Column(db.Float, default=0.0)
    reviews_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert product object to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'category': self.category,
            'brand': self.brand,
            'stock_quantity': self.stock_quantity,
            'sku': self.sku,
            'image_url': self.image_url,
            'rating': self.rating,
            'reviews_count': self.reviews_count,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class ChatSession(db.Model):
    """Chat session model to track user interactions"""
    __tablename__ = 'chat_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    messages = db.relationship('ChatMessage', backref='session', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert chat session object to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_token': self.session_token,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'is_active': self.is_active,
            'message_count': len(self.messages)
        }

class ChatMessage(db.Model):
    """Chat message model to store conversation history"""
    __tablename__ = 'chat_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_sessions.id'), nullable=False)
    sender_type = db.Column(db.String(20), nullable=False)  # 'user' or 'bot'
    message_text = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(50), default='text')  # 'text', 'product_list', 'system'
    meta_info = db.Column(db.JSON)  # Store additional data like product IDs, filters, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert chat message object to dictionary"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'sender_type': self.sender_type,
            'message_text': self.message_text,
            'message_type': self.message_type,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

# ========================= HELPER FUNCTIONS =========================

def require_auth(f):
    """Decorator to require authentication for certain endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            # In a real application, you would validate the JWT token here
            # For now, we'll use a simple session-based approach
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401
    
    return decorated_function

def generate_session_token():
    """Generate a unique session token"""
    import secrets
    return secrets.token_urlsafe(32)

class ChatbotEngine:
    """Simple chatbot engine for processing user queries"""
    
    def __init__(self):
        self.product_keywords = {
            'electronics': ['laptop', 'computer', 'phone', 'tablet', 'headphones', 'camera', 'tv', 'monitor'],
            'books': ['book', 'novel', 'textbook', 'magazine', 'ebook', 'kindle', 'reading'],
            'clothing': ['shirt', 'pants', 'dress', 'shoes', 'jacket', 'jeans', 'clothing', 'apparel'],
            'home': ['furniture', 'lamp', 'chair', 'table', 'bed', 'sofa', 'kitchen', 'home'],
            'sports': ['sports', 'fitness', 'gym', 'exercise', 'running', 'yoga', 'bike', 'outdoor']
        }
        
        self.price_patterns = [
            r'under\s*\$?(\d+)',
            r'below\s*\$?(\d+)',
            r'less\s*than\s*\$?(\d+)',
            r'cheaper\s*than\s*\$?(\d+)',
            r'budget\s*of\s*\$?(\d+)',
            r'between\s*\$?(\d+)\s*and\s*\$?(\d+)',
            r'from\s*\$?(\d+)\s*to\s*\$?(\d+)'
        ]
    
    def process_message(self, message, user_id=None):
        """Process user message and return appropriate response"""
        message_lower = message.lower().strip()
        
        # Handle greetings
        if any(greeting in message_lower for greeting in ['hello', 'hi', 'hey', 'good morning', 'good afternoon']):
            return {
                'type': 'greeting',
                'message': "Hello! I'm your personal shopping assistant. How can I help you find the perfect product today?",
                'suggestions': [
                    "Show me laptops under $800",
                    "I need a gift for my friend",
                    "What's on sale today?",
                    "Best smartphones this year"
                ]
            }
        
        # Handle help requests
        if any(help_word in message_lower for help_word in ['help', 'assist', 'support']):
            return {
                'type': 'help',
                'message': "I can help you with:\n• Searching for products by name or category\n• Finding products within your budget\n• Comparing product features\n• Getting product recommendations\n\nJust tell me what you're looking for!",
                'suggestions': [
                    "Search for wireless headphones",
                    "Show me books about Python programming",
                    "Find me a jacket under $100"
                ]
            }
        
        # Extract product search intent
        category = self._extract_category(message_lower)
        price_range = self._extract_price_range(message_lower)
        search_terms = self._extract_search_terms(message_lower)
        
        # Build search filters
        filters = {}
        if category:
            filters['category'] = category
        if price_range:
            filters['price_range'] = price_range
        if search_terms:
            filters['search_terms'] = search_terms
        
        return {
            'type': 'product_search',
            'message': f"I found some great products for you!",
            'filters': filters,
            'search_query': message
        }
    
    def _extract_category(self, message):
        """Extract product category from message"""
        for category, keywords in self.product_keywords.items():
            if any(keyword in message for keyword in keywords):
                return category
        return None
    
    def _extract_price_range(self, message):
        """Extract price range from message"""
        for pattern in self.price_patterns:
            match = re.search(pattern, message)
            if match:
                if 'between' in pattern or 'from' in pattern:
                    return {'min': int(match.group(1)), 'max': int(match.group(2))}
                else:
                    return {'max': int(match.group(1))}
        return None
    
    def _extract_search_terms(self, message):
        """Extract search terms from message"""
        # Remove common stop words and extract meaningful terms
        stop_words = {'i', 'need', 'want', 'looking', 'for', 'show', 'me', 'find', 'get', 'buy', 'a', 'an', 'the', 'some', 'any'}
        words = message.split()
        search_terms = [word for word in words if word not in stop_words and len(word) > 2]
        return search_terms[:5]  # Limit to 5 most relevant terms

# Initialize chatbot engine
chatbot = ChatbotEngine()

# ========================= API ROUTES =========================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password are required'}), 400
        
        username = data['username'].strip()
        password = data['password']
        email = data.get('email', '').strip()
        
        # Validate username
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long'}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        if email and User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create new user
        user = User(username=username, email=email if email else None)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"New user registered: {username}")
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password are required'}), 400
        
        username = data['username'].strip()
        password = data['password']
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 401
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Create access token
        access_token = create_access_token(identity=user.id)
        
        # Create chat session
        session_token = generate_session_token()
        chat_session = ChatSession(
            user_id=user.id,
            session_token=session_token
        )
        db.session.add(chat_session)
        db.session.commit()
        
        logger.info(f"User logged in: {username}")
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'session_token': session_token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout endpoint"""
    try:
        user_id = get_jwt_identity()
        session_token = request.json.get('session_token')
        
        if session_token:
            # End chat session
            chat_session = ChatSession.query.filter_by(
                user_id=user_id,
                session_token=session_token,
                is_active=True
            ).first()
            
            if chat_session:
                chat_session.is_active = False
                chat_session.ended_at = datetime.utcnow()
                db.session.commit()
        
        logger.info(f"User logged out: {user_id}")
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@app.route('/api/products/search', methods=['GET', 'POST'])
def search_products():
    """Product search endpoint"""
    try:
        if request.method == 'POST':
            data = request.get_json()
            query = data.get('query', '')
            filters = data.get('filters', {})
        else:
            query = request.args.get('query', '')
            filters = {}
            
            # Extract filters from query parameters
            if request.args.get('category'):
                filters['category'] = request.args.get('category')
            if request.args.get('min_price'):
                filters['min_price'] = float(request.args.get('min_price'))
            if request.args.get('max_price'):
                filters['max_price'] = float(request.args.get('max_price'))
        
        # Build query
        products_query = Product.query.filter(Product.is_active == True)
        
        # Apply text search
        if query:
            search_pattern = f"%{query}%"
            products_query = products_query.filter(
                db.or_(
                    Product.name.ilike(search_pattern),
                    Product.description.ilike(search_pattern),
                    Product.brand.ilike(search_pattern),
                    Product.category.ilike(search_pattern)
                )
            )
        
        # Apply filters
        if filters.get('category'):
            products_query = products_query.filter(Product.category == filters['category'])
        
        if filters.get('min_price'):
            products_query = products_query.filter(Product.price >= filters['min_price'])
        
        if filters.get('max_price'):
            products_query = products_query.filter(Product.price <= filters['max_price'])
        
        if filters.get('price_range'):
            price_range = filters['price_range']
            if isinstance(price_range, dict):
                if price_range.get('min'):
                    products_query = products_query.filter(Product.price >= price_range['min'])
                if price_range.get('max'):
                    products_query = products_query.filter(Product.price <= price_range['max'])
        
        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)
        
        products_paginated = products_query.order_by(Product.rating.desc(), Product.name).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        products = [product.to_dict() for product in products_paginated.items]
        
        return jsonify({
            'products': products,
            'total': products_paginated.total,
            'pages': products_paginated.pages,
            'current_page': page,
            'per_page': per_page,
            'has_next': products_paginated.has_next,
            'has_prev': products_paginated.has_prev
        }), 200
        
    except Exception as e:
        logger.error(f"Product search error: {str(e)}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    """Get single product by ID"""
    try:
        product = Product.query.filter_by(id=product_id, is_active=True).first()
        
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        return jsonify({'product': product.to_dict()}), 200
        
    except Exception as e:
        logger.error(f"Get product error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve product'}), 500

@app.route('/api/products/categories', methods=['GET'])
def get_categories():
    """Get all product categories"""
    try:
        categories = db.session.query(Product.category).filter(Product.is_active == True).distinct().all()
        category_list = [category[0] for category in categories]
        
        return jsonify({'categories': category_list}), 200
        
    except Exception as e:
        logger.error(f"Get categories error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve categories'}), 500

@app.route('/api/chat/message', methods=['POST'])
@jwt_required()
def process_chat_message():
    """Process chat message and return bot response"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data or not data.get('message'):
            return jsonify({'error': 'Message is required'}), 400
        
        message = data['message'].strip()
        session_token = data.get('session_token')
        
        # Find or create chat session
        chat_session = None
        if session_token:
            chat_session = ChatSession.query.filter_by(
                user_id=user_id,
                session_token=session_token,
                is_active=True
            ).first()
        
        if not chat_session:
            session_token = generate_session_token()
            chat_session = ChatSession(
                user_id=user_id,
                session_token=session_token
            )
            db.session.add(chat_session)
            db.session.flush()
        
        # Save user message
        user_message = ChatMessage(
            session_id=chat_session.id,
            sender_type='user',
            message_text=message,
            message_type='text'
        )
        db.session.add(user_message)
        
        # Process message with chatbot
        bot_response = chatbot.process_message(message, user_id)
        
        # Handle product search
        products = []
        if bot_response['type'] == 'product_search':
            filters = bot_response.get('filters', {})
            
            # Search for products
            products_query = Product.query.filter(Product.is_active == True)
            
            if filters.get('category'):
                products_query = products_query.filter(Product.category == filters['category'])
            
            if filters.get('price_range'):
                price_range = filters['price_range']
                if price_range.get('min'):
                    products_query = products_query.filter(Product.price >= price_range['min'])
                if price_range.get('max'):
                    products_query = products_query.filter(Product.price <= price_range['max'])
            
            if filters.get('search_terms'):
                search_terms = filters['search_terms']
                for term in search_terms:
                    search_pattern = f"%{term}%"
                    products_query = products_query.filter(
                        db.or_(
                            Product.name.ilike(search_pattern),
                            Product.description.ilike(search_pattern),
                            Product.brand.ilike(search_pattern)
                        )
                    )
            
            found_products = products_query.order_by(Product.rating.desc()).limit(5).all()
            products = [product.to_dict() for product in found_products]
            
            if not products:
                bot_response['message'] = "I couldn't find any products matching your criteria. Try adjusting your search terms or filters."
            else:
                bot_response['message'] = f"I found {len(products)} products that match your search!"
        
        # Save bot response
        bot_message = ChatMessage(
            session_id=chat_session.id,
            sender_type='bot',
            message_text=bot_response['message'],
            message_type=bot_response['type'],
            metadata={
                'products': [p['id'] for p in products] if products else None,
                'filters': bot_response.get('filters'),
                'suggestions': bot_response.get('suggestions')
            }
        )
        db.session.add(bot_message)
        
        db.session.commit()
        
        return jsonify({
            'bot_response': bot_response['message'],
            'message_type': bot_response['type'],
            'products': products,
            'suggestions': bot_response.get('suggestions', []),
            'session_token': session_token,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Chat message error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to process message'}), 500

@app.route('/api/chat/history', methods=['GET'])
@jwt_required()
def get_chat_history():
    """Get chat history for user"""
    try:
        user_id = get_jwt_identity()
        session_token = request.args.get('session_token')
        limit = min(request.args.get('limit', 50, type=int), 100)
        
        # Get chat session
        chat_session = ChatSession.query.filter_by(
            user_id=user_id,
            session_token=session_token
        ).first()
        
        if not chat_session:
            return jsonify({'messages': []}), 200
        
        # Get messages
        messages = ChatMessage.query.filter_by(
            session_id=chat_session.id
        ).order_by(ChatMessage.timestamp.desc()).limit(limit).all()
        
        messages_data = []
        for message in reversed(messages):
            message_dict = message.to_dict()
            
            # Add products if available
            if message.metadata and message.metadata.get('products'):
                product_ids = message.metadata['products']
                products = Product.query.filter(Product.id.in_(product_ids)).all()
                message_dict['products'] = [p.to_dict() for p in products]
            
            messages_data.append(message_dict)
        
        return jsonify({
            'messages': messages_data,
            'session': chat_session.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Get chat history error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve chat history'}), 500

@app.route('/api/chat/sessions', methods=['GET'])
@jwt_required()
def get_chat_sessions():
    """Get all chat sessions for user"""
    try:
        user_id = get_jwt_identity()
        
        sessions = ChatSession.query.filter_by(user_id=user_id).order_by(
            ChatSession.started_at.desc()
        ).all()
        
        sessions_data = [session.to_dict() for session in sessions]
        
        return jsonify({'sessions': sessions_data}), 200
        
    except Exception as e:
        logger.error(f"Get chat sessions error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve chat sessions'}), 500
###---------------------------------------------------------------------
@app.route("/api/send", methods=["POST"])
def receive_message():
    data = request.get_json()
    message = data.get("message")

    # (Optional) Process message using logic or ML model
    bot_reply = f"You said: {message}"
    print("📩 Received from frontend:", message)

    return jsonify({
        "reply": f"You said: {message}",
        "products": []  # Optionally return products
    })
    #return jsonify({
        #"reply": bot_reply,
        #"products": [] # Can include product data too
    #})


# ========================= ADMIN ENDPOINTS =========================

@app.route('/api/admin/products', methods=['POST'])
def create_product():
    """Create new product (admin endpoint)"""
    try:
        data = request.get_json()
        
        if not data or not data.get('name') or not data.get('price'):
            return jsonify({'error': 'Name and price are required'}), 400
        
        product = Product(
            name=data['name'],
            description=data.get('description', ''),
            price=float(data['price']),
            category=data.get('category', 'general'),
            brand=data.get('brand', ''),
            stock_quantity=data.get('stock_quantity', 0),
            sku=data.get('sku'),
            image_url=data.get('image_url'),
            rating=data.get('rating', 0.0),
            reviews_count=data.get('reviews_count', 0)
        )
        
        db.session.add(product)
        db.session.commit()
        
        logger.info(f"New product created: {product.name}")
        
        return jsonify({
            'message': 'Product created successfully',
            'product': product.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Create product error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to create product'}), 500

# ========================= INITIALIZATION =========================

def create_sample_data():
  
    """Create sample products for testing"""
    if Product.query.count() > 0:
        return  # Data already exists
    
    logger.info("Creating sample product data...")
    
    sample_products = [
        # Electronics
        {
            'name': 'MacBook Pro 14-inch',
            'description': 'Apple MacBook Pro with M2 chip, 16GB RAM, 512GB SSD. Perfect for professionals.',
            'price': 1999.99,
            'category': 'electronics',
            'brand': 'Apple',
            'stock_quantity': 15,
            'sku': 'MBP-14-M2-512',
            'rating': 4.8,
            'reviews_count': 245
        },
        {
            'name': 'iPhone 15 Pro',
            'description': 'Latest iPhone with A17 Pro chip, 128GB storage, ProRAW camera capabilities.',
            'price': 999.99,
            'category': 'electronics',
            'brand': 'Apple',
            'stock_quantity': 25,
            'sku': 'IPH-15-PRO-128',
            'rating': 4.7,
            'reviews_count': 189
        },
        {
            'name': 'Samsung Galaxy S24 Ultra',
            'description': 'Premium Android smartphone with S Pen, 256GB storage, and advanced camera system.',
            'price': 1199.99,
            'category': 'electronics',
            'brand': 'Samsung',
            'stock_quantity': 18,
            'sku': 'SGS24U-256',
            'rating': 4.6,
            'reviews_count': 156
        },
        {
            'name': 'Sony WH-1000XM5',
            'description': 'Industry-leading noise canceling wireless headphones with 30-hour battery life.',
            'price': 399.99,
            'category': 'electronics',
            'brand': 'Sony',
            'stock_quantity': 35,
            'sku': 'WH1000XM5-B',
            'rating': 4.9,
            'reviews_count': 312
        },
        {
            'name': 'Dell XPS 13',
            'description': 'Ultra-portable laptop with Intel i7, 16GB RAM, 512GB SSD, and InfinityEdge display.',
            'price': 1299.99,
            'category': 'electronics',
            'brand': 'Dell',
            'stock_quantity': 12,
            'sku': 'XPS13-I7-512',
            'rating': 4.5,
            'reviews_count': 203
        },
        
        # Clothing
        {
            'name': 'Nike Air Max 270',
            'description': 'Comfortable running shoes with Max Air unit and breathable mesh upper.',
            'price': 150.00,
            'category': 'clothing',
            'brand': 'Nike',
            'stock_quantity': 42,
            'sku': 'AM270-BLK-10',
            'rating': 4.4,
            'reviews_count': 89
        },
        {
            'name': 'Levi\'s 501 Original Jeans',
            'description': 'Classic straight-leg jeans in vintage wash. Made with premium cotton denim.',
            'price': 89.99,
            'category': 'clothing',
            'brand': 'Levi\'s',
            'stock_quantity': 38,
            'sku': 'LV501-VW-32',
            'rating': 4.3,
            'reviews_count': 127
        },
        {
            'name': 'Adidas Ultraboost 22',
            'description': 'Performance running shoes with responsive Boost midsole and Primeknit upper.',
            'price': 190.00,
            'category': 'clothing',
            'brand': 'Adidas',
            'stock_quantity': 28,
            'sku': 'UB22-WHT-9',
            'rating': 4.6,
            'reviews_count': 94
        },
        {
            'name': 'Patagonia Better Sweater',
            'description': 'Fleece jacket made from recycled polyester. Perfect for outdoor activities.',
            'price': 119.00,
            'category': 'clothing',
            'brand': 'Patagonia',
            'stock_quantity': 22,
            'sku': 'PB-SWTR-NAV-L',
            'rating': 4.7,
            'reviews_count': 76
        },
        
        # Home & Garden
        {
            'name': 'Dyson V15 Detect',
            'description': 'Cordless vacuum with laser dust detection and 60 minutes of fade-free power.',
            'price': 749.99,
            'category': 'home_garden',
            'brand': 'Dyson',
            'stock_quantity': 8,
            'sku': 'DV15-DETECT',
            'rating': 4.8,
            'reviews_count': 167
        },
        {
            'name': 'KitchenAid Stand Mixer',
            'description': 'Professional 5-quart stand mixer with 10 speeds and multiple attachments included.',
            'price': 449.99,
            'category': 'home_garden',
            'brand': 'KitchenAid',
            'stock_quantity': 14,
            'sku': 'KA-SM-RED-5Q',
            'rating': 4.9,
            'reviews_count': 289
        },
        {
            'name': 'Weber Genesis II Gas Grill',
            'description': '3-burner propane gas grill with porcelain-enameled cast-iron grates.',
            'price': 899.00,
            'category': 'home_garden',
            'brand': 'Weber',
            'stock_quantity': 6,
            'sku': 'WG-GEN2-3B',
            'rating': 4.6,
            'reviews_count': 134
        },
        {
            'name': 'Nest Learning Thermostat',
            'description': 'Smart thermostat that learns your schedule and programs itself to save energy.',
            'price': 249.99,
            'category': 'home_garden',
            'brand': 'Google',
            'stock_quantity': 31,
            'sku': 'NEST-THERM-3',
            'rating': 4.4,
            'reviews_count': 198
        },
        
        # Books
        {
            'name': 'The Seven Husbands of Evelyn Hugo',
            'description': 'A captivating novel about a reclusive Hollywood icon who reveals her secrets.',
            'price': 16.99,
            'category': 'books',
            'brand': 'St. Martin\'s Press',
            'stock_quantity': 67,
            'sku': 'BOOK-7H-EH',
            'rating': 4.9,
            'reviews_count': 423
        },
        {
            'name': 'Atomic Habits',
            'description': 'An Easy & Proven Way to Build Good Habits & Break Bad Ones by James Clear.',
            'price': 18.00,
            'category': 'books',
            'brand': 'Avery',
            'stock_quantity': 45,
            'sku': 'BOOK-AT-HAB',
            'rating': 4.8,
            'reviews_count': 567
        },
        {
            'name': 'Dune: Complete Series',
            'description': 'Frank Herbert\'s epic science fiction masterpiece - complete 6-book series.',
            'price': 89.99,
            'category': 'books',
            'brand': 'Ace Books',
            'stock_quantity': 23,
            'sku': 'BOOK-DUNE-SET',
            'rating': 4.7,
            'reviews_count': 189
        },
        
        # Sports
        {
            'name': 'Peloton Bike+',
            'description': 'Premium indoor cycling bike with rotating HD touchscreen and live classes.',
            'price': 2495.00,
            'category': 'sports',
            'brand': 'Peloton',
            'stock_quantity': 4,
            'sku': 'PELO-BIKE-PLUS',
            'rating': 4.5,
            'reviews_count': 234
        },
        {
            'name': 'NordicTrack Treadmill',
            'description': 'Commercial-grade treadmill with iFit technology and incline training.',
            'price': 1799.00,
            'category': 'sports',
            'brand': 'NordicTrack',
            'stock_quantity': 7,
            'sku': 'NT-TM-COMM',
            'rating': 4.3,
            'reviews_count': 145
        },
        {
            'name': 'Bowflex SelectTech Dumbbells',
            'description': 'Adjustable dumbbells that replace 15 sets of weights (5-52.5 lbs each).',
            'price': 399.00,
            'category': 'sports',
            'brand': 'Bowflex',
            'stock_quantity': 16,
            'sku': 'BF-ST-552',
            'rating': 4.6,
            'reviews_count': 178
        },
        {
            'name': 'Yeti Rambler Tumbler',
            'description': '20oz stainless steel tumbler with MagSlider lid. Keeps drinks hot or cold.',
            'price': 34.99,
            'category': 'sports',
            'brand': 'Yeti',
            'stock_quantity': 89,
            'sku': 'YETI-RAM-20',
            'rating': 4.8,
            'reviews_count': 267
        }
    ]
    
    try:
        for product_data in sample_products:
            product = Product(**product_data)
            db.session.add(product)
        
        db.session.commit()
        logger.info(f"Successfully created {len(sample_products)} sample products")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating sample data: {str(e)}")
        raise
if __name__ == "__main__":
    app.run(debug=True)
