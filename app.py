from functools import lru_cache, wraps
import os
from os import environ, getenv
from os.path import dirname, join
from datetime import datetime, timedelta

from dotenv import load_dotenv
from firebase_admin import credentials, firestore, initialize_app, storage
from flask import Flask, json, redirect, render_template, request, flash, session, jsonify, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# Import our Firebase configuration
from firebase_config import initialize_firebase, check_emulator_mode

# Initialize Flask app
app = Flask(__name__)
app.secret_key = getenv("SECRET_KEY", "dev-secret-key-change-in-production")

# Read environment variables set at ./.env
if not load_dotenv(f"{dirname(__file__)}/.env"):
    # In production (Vercel), .env file might not exist, which is fine
    # Environment variables will be set through Vercel's interface
    pass


def check_if_required_env_variables_are_present():
    required_env_variables = {
        "START_ACT",
        "END_ACT",
        "CURRENT_ACT_YEAR",
        "FIREBASE_STORAGE",
        "SECRET_KEY",
    }

    # In production, we also need Firebase service account variables
    if not os.path.exists("firebase.json"):
        firebase_env_vars = {
            "FIREBASE_PROJECT_ID",
            "FIREBASE_PRIVATE_KEY_ID", 
            "FIREBASE_PRIVATE_KEY",
            "FIREBASE_CLIENT_EMAIL",
            "FIREBASE_CLIENT_ID",
            "FIREBASE_CLIENT_X509_CERT_URL"
        }
        required_env_variables.update(firebase_env_vars)

    missing_vars = [var for var in required_env_variables if var not in environ]
    if missing_vars:
        raise RuntimeError(
            f"The following required environmental variables have not been set: {missing_vars}"
        )


check_if_required_env_variables_are_present()


# Initialize Firebase and Firestore
db = initialize_firebase()


# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('cyscom_login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('cyscom_login'))
        
        user = get_current_user()
        if not user or user.get('role') not in ['admin', 'cabinet']:
            flash('Access denied. Admin or Cabinet privileges required.', 'error')
            return redirect(url_for('leaderboard'))
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    if 'user_id' not in session:
        return None
    
    try:
        user_doc = db.collection('users').document(session['user_id']).get()
        if user_doc.exists:
            return user_doc.to_dict()
        return None
    except Exception:
        return None


def fetch_data(act: int | str) -> list[dict]:
    """Return a list of all members in the act. Sorted by points"""
    try:
        # Get all members from the act collection
        members_ref = db.collection('leaderboard').document(f'act{act}').collection('members')
        docs = members_ref.stream()
        
        users_of_act = []
        for doc in docs:
            member_data = doc.to_dict()
            member_data['id'] = doc.id  # Add document ID
            users_of_act.append(member_data)
        
        # Sort by Rating (points) in descending order
        users_of_act.sort(key=lambda x: x.get("Rating", 0), reverse=True)
        return users_of_act
    except Exception as e:
        print(f"Error fetching data for act {act}: {e}")
        return []


class Act:
    def __init__(self, num: int, name: str):
        self.num: int = num
        self.name: str = name
        self.data: list

        # Fetch data from leaderboard
        self.refresh_leaderboard_data()

        self.cabinet = list(
            filter(
                lambda member: (member["Rating"] >= 5000)
                and member["Name"].casefold() != "testing",
                self.data,
            )
        )
        self.members = list(
            filter(
                lambda member: (
                    member["Rating"] < 5000 and member["Name"].casefold() != "testing"
                ),
                self.data,
            )
        )
        self.rank_members()

    def refresh_leaderboard_data(self):
        print("fetched latest points")
        self.data = fetch_data(self.num)

    def rank_members(self):
        # Base thresholds (starting point)
        base_diamond_threshold = 270
        base_platinum_threshold = 180
        base_gold_threshold = 100
        
        # Target population limits per tier
        MAX_DIAMOND_POPULATION = 8
        MAX_PLATINUM_POPULATION = 12
        MAX_GOLD_POPULATION = 15
        
        # Sort all members by rating (descending) to analyze population
        self.members.sort(key=lambda x: x.get("Rating", 0), reverse=True)
        
        # Calculate dynamic thresholds based on population density
        diamond_threshold = self._calculate_dynamic_threshold(
            base_diamond_threshold, MAX_DIAMOND_POPULATION, "diamond"
        )
        platinum_threshold = self._calculate_dynamic_threshold(
            base_platinum_threshold, MAX_PLATINUM_POPULATION, "platinum"  
        )
        gold_threshold = self._calculate_dynamic_threshold(
            base_gold_threshold, MAX_GOLD_POPULATION, "gold"
        )
        
        # Apply rankings with dynamic thresholds
        for member in self.members:
            rating = member.get("Rating", 0)
            
            if rating >= diamond_threshold:
                # Diamond tier - assign sub-ranks based on score within diamond
                diamond_range = max(50, (max([m["Rating"] for m in self.members if m["Rating"] >= diamond_threshold]) - diamond_threshold) / 3)
                if rating >= diamond_threshold + (2 * diamond_range):
                    member["Image"] = "diamond-3"  # Highest diamond
                elif rating >= diamond_threshold + diamond_range:
                    member["Image"] = "diamond-2"  # Mid diamond
                else:
                    member["Image"] = "diamond-1"  # Lower diamond
                    
            elif rating >= platinum_threshold:
                # Platinum tier - assign sub-ranks based on score within platinum
                platinum_range = max(30, (diamond_threshold - platinum_threshold) / 3)
                if rating >= platinum_threshold + (2 * platinum_range):
                    member["Image"] = "platinum-3"  # Highest platinum
                elif rating >= platinum_threshold + platinum_range:
                    member["Image"] = "platinum-2"  # Mid platinum
                else:
                    member["Image"] = "platinum-1"  # Lower platinum
                    
            elif rating >= gold_threshold:
                # Gold tier - assign sub-ranks based on score within gold
                gold_range = max(25, (platinum_threshold - gold_threshold) / 3)
                if rating >= gold_threshold + (2 * gold_range):
                    member["Image"] = "gold-3"  # Highest gold
                elif rating >= gold_threshold + gold_range:
                    member["Image"] = "gold-2"  # Mid gold
                else:
                    member["Image"] = "gold-1"  # Lower gold
                    
            elif rating >= 75:
                # Silver tier (75-99)
                if rating >= 90:
                    member["Image"] = "silver-3"
                elif rating >= 85:
                    member["Image"] = "silver-2"
                else:
                    member["Image"] = "silver-1"
                    
            elif rating >= 50:
                # Bronze tier (50-74)
                if rating >= 65:
                    member["Image"] = "bronze-3"
                elif rating >= 60:
                    member["Image"] = "bronze-2"
                else:
                    member["Image"] = "bronze-1"
                    
            elif rating >= 25:
                # Iron tier (25-49)
                if rating >= 40:
                    member["Image"] = "iron-3"
                elif rating >= 35:
                    member["Image"] = "iron-2"
                else:
                    member["Image"] = "iron-1"
                    
            elif rating > 0:
                member["Image"] = "iron-1"
            else:
                member["Image"] = "unranked"
    
    def _calculate_dynamic_threshold(self, base_threshold: int, max_population: int, tier_name: str) -> int:
        """
        Calculate dynamic threshold based on population density.
        If too many people qualify for a tier, raise the threshold.
        """
        # Count how many members would qualify with base threshold
        qualified_count = len([m for m in self.members if m.get("Rating", 0) >= base_threshold])
        
        if qualified_count <= max_population:
            # Population within limits, use base threshold
            return base_threshold
        
        # Too many people qualified, need to raise threshold
        # Get all scores of qualified members, sorted descending
        qualified_scores = sorted([m["Rating"] for m in self.members if m.get("Rating", 0) >= base_threshold], reverse=True)
        
        if len(qualified_scores) >= max_population:
            # Set threshold to the score of the (max_population)th person
            # This ensures exactly max_population people qualify
            new_threshold = qualified_scores[max_population - 1]
            
            # Add small buffer to avoid ties at the boundary
            new_threshold += 1
            
            print(f"🔄 {tier_name.title()} threshold adjusted: {base_threshold} → {new_threshold} (population: {qualified_count} → ~{max_population})")
            return new_threshold
        
        return base_threshold


CURRENT_ACT_YEAR: int = int(getenv("CURRENT_ACT_YEAR"))
END_ACT: int = int(getenv("END_ACT"))
START_ACT: int = int(getenv("START_ACT"))

# Point Categories System
POINT_CATEGORIES = {
    # Pull Request Contributions
    "easy_pr": {"name": "Easy PR", "points": 20, "category": "Development"},
    "medium_pr": {"name": "Medium PR", "points": 40, "category": "Development"},
    "hard_pr": {"name": "Hard PR", "points": 80, "category": "Development"},
    
    # CTF Contributions
    "ctf_host": {"name": "CTF Host", "points": 30, "category": "CTF"},
    "ctf_attendee": {"name": "CTF Attendee", "points": 10, "category": "CTF"},
    "ctf_easy_challenge": {"name": "CTF Easy Challenge", "points": 20, "category": "CTF"},
    "ctf_medium_challenge": {"name": "CTF Medium Challenge", "points": 40, "category": "CTF"},
    "ctf_hard_challenge": {"name": "CTF Hard Challenge", "points": 80, "category": "CTF"},
    
    # Content Creation
    "info_content": {"name": "Info Content", "points": 40, "category": "Content"},
    "blog_content": {"name": "Blog Content", "points": 60, "category": "Content"},
    "news_content": {"name": "News Content", "points": 40, "category": "Content"},
    "sm_posting": {"name": "Social Media Posting", "points": 15, "category": "Content"},
    "caption": {"name": "Caption", "points": 5, "category": "Content"},
    
    # Organizational
    "subordinate": {"name": "Subordinate", "points": 20, "category": "Organization"},
    "idea": {"name": "Idea", "points": 3, "category": "Organization"},
    "brochure": {"name": "Brochure", "points": 10, "category": "Organization"},
    "demos": {"name": "Demos", "points": 20, "category": "Organization"},
    "video_editing": {"name": "Video Editing", "points": 20, "category": "Organization"},
    
    # Organizational Committee
    "oc_volunteer": {"name": "OC Volunteer", "points": 30, "category": "OC"},
    "oc_assigned": {"name": "OC Assigned", "points": 20, "category": "OC"},
    "oc_no_work": {"name": "OC No Work", "points": 10, "category": "OC"},
    "oc_manager": {"name": "OC Manager", "points": 50, "category": "OC"},
    
    # Event Management
    "em_lite": {"name": "EM Lite", "points": 15, "category": "Events"},
    "em_medium": {"name": "EM Medium", "points": 30, "category": "Events"},
    "em_heavy": {"name": "EM Heavy", "points": 60, "category": "Events"},
    
    # Social Functions
    "sf_lite": {"name": "SF Lite", "points": 30, "category": "Social"},
    "sf_medium": {"name": "SF Medium", "points": 60, "category": "Social"},
    "wtf": {"name": "WTF", "points": 75, "category": "Social"},
    
    # Community & Marketing
    "discord": {"name": "Discord", "points": 10, "category": "Community"},
    "marketing": {"name": "Marketing", "points": 20, "category": "Community"},
    
    # Projects
    "mini_project": {"name": "Mini Project", "points": 100, "category": "Projects"},
    "complete_project": {"name": "Complete Project", "points": 200, "category": "Projects"},
    
    # Promotions
    "promotion_medium": {"name": "Promotion Medium", "points": 25, "category": "Promotion"},
    "promotion_large": {"name": "Promotion Large", "points": 50, "category": "Promotion"},
    
    # Design Work
    "blog_design": {"name": "Blog Design", "points": 35, "category": "Design"},
    "info_design": {"name": "Info Design", "points": 45, "category": "Design"},
    "news_design": {"name": "News Design", "points": 45, "category": "Design"},
    "weekly_work_design": {"name": "Weekly Work Design", "points": 40, "category": "Design"}
}


@app.route("/", methods=["GET"])
def index():
    return redirect("/leaderboard")


@app.route("/leaderboard", methods=["GET"])
def leaderboard():
    all_acts = [
        Act(i, f"ACT {i} - {CURRENT_ACT_YEAR - END_ACT + i}")
        for i in range(END_ACT, START_ACT, -1)
    ]
    current_user = get_current_user()
    
    # Get current Wizard of the Fortnight (only for current ACT)
    fort_night = None
    try:
        wizard_doc = db.collection('announcements').document('current_wizard').get()
        if wizard_doc.exists:
            wizard_data = wizard_doc.to_dict()
            
            # Check if wizard is active and not expired
            if wizard_data.get("active", False):
                # Check expiration (14 days from creation)
                created_at_str = wizard_data.get("created_at")
                if created_at_str:
                    try:
                        created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                        # Remove timezone info for comparison if present
                        if created_at.tzinfo:
                            created_at = created_at.replace(tzinfo=None)
                        
                        days_elapsed = (datetime.now() - created_at).days
                        
                        if days_elapsed >= 14:
                            # Wizard has expired, deactivate it
                            wizard_data["active"] = False
                            wizard_data["expired_at"] = datetime.now().isoformat()
                            wizard_data["updated_at"] = datetime.now().isoformat()
                            wizard_data["updated_by"] = "System (Auto-expired)"
                            
                            # Update in database
                            db.collection('announcements').document('current_wizard').set(wizard_data)
                            print(f"Wizard '{wizard_data.get('wizard_name')}' auto-expired after {days_elapsed} days")
                        else:
                            # Wizard is still active, show it
                            fort_night = wizard_data
                    except Exception as date_error:
                        print(f"Error parsing wizard creation date: {date_error}")
                        # If date parsing fails, assume expired for safety
                        wizard_data["active"] = False
                        wizard_data["expired_at"] = datetime.now().isoformat()
                        wizard_data["updated_at"] = datetime.now().isoformat()
                        wizard_data["updated_by"] = "System (Date parsing failed)"
                        db.collection('announcements').document('current_wizard').set(wizard_data)
    except Exception as e:
        print(f"Error fetching Wizard: {e}")
    
    # Create JSON data for JavaScript
    all_acts_json = {}
    for act in all_acts:
        all_acts_json[f'act{act.num}'] = {
            'members': [{'name': member['Name'], 'rating': member['Rating']} for member in act.members],
            'cabinet': [{'name': member['Name'], 'rating': member['Rating']} for member in act.cabinet]
        }
    
    return render_template("leaderboard.html", all_acts=all_acts, enumerate=enumerate, 
                         current_user=current_user, fort_night=fort_night, all_acts_json=json.dumps(all_acts_json),
                         point_categories=POINT_CATEGORIES)


# Authentication Routes
@app.route("/login", methods=["GET", "POST"])
def login():
    # Redirect to the hidden endpoint
    return redirect(url_for("cyscom_login"))


@app.route("/cyscom", methods=["GET", "POST"])
def cyscom_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            flash("Please provide both username and password.", "error")
            return render_template("login.html")
        
        # Check all users to find matching username
        try:
            users_collection = db.collection('users')
            users_query = users_collection.where('username', '==', username).limit(1)
            users = list(users_query.stream())
            
            if users:
                user_doc = users[0]
                user_data = user_doc.to_dict()
                user_id = user_doc.id
                
                if check_password_hash(user_data.get("password_hash", ""), password):
                    session['user_id'] = user_id
                    session['username'] = user_data.get("username")
                    session['role'] = user_data.get("role", "user")
                    
                    # Welcome message with role context
                    role = user_data.get("role", "user")
                    if role in ["admin", "cabinet"]:
                        flash(f"Welcome back, {user_data.get('name', username)}! You can now manage the leaderboard.", "success")
                    else:
                        flash(f"Welcome back, {user_data.get('name', username)}!", "success")
                    
                    # Update last login
                    user_doc.reference.update({'last_login': datetime.now().isoformat()})
                    
                    # Always redirect to leaderboard (admin features are inline)
                    return redirect(url_for("leaderboard"))
                else:
                    flash("Invalid username or password.", "error")
            else:
                flash("Invalid username or password.", "error")
                
        except Exception as e:
            flash("An error occurred during login. Please try again.", "error")
            print(f"Login error: {e}")
    
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("leaderboard"))


# Admin Routes (Dashboard route deprecated - all functionality is now inline on leaderboard)
@app.route("/admin")
@admin_required
def admin_dashboard():
    # Redirect to leaderboard - all admin features are available inline
    flash("All admin features are now available directly on the leaderboard!", "info")
    return redirect(url_for("leaderboard"))


@app.route("/admin/members")
@admin_required
def admin_members():
    current_user = get_current_user()
    
    # Get act number from query parameter, default to latest act
    act_num = request.args.get("act", END_ACT, type=int)
    
    if act_num < START_ACT or act_num > END_ACT:
        act_num = END_ACT
    
    members = fetch_data(act_num)
    
    return render_template("admin/members.html", 
                         current_user=current_user, 
                         members=members, 
                         current_act=act_num,
                         start_act=START_ACT,
                         end_act=END_ACT)


@app.route("/admin/members/add", methods=["GET", "POST"])
@admin_required
def admin_add_member():
    current_user = get_current_user()
    
    if request.method == "POST":
        try:
            name = request.form.get("name", "").strip()
            rating = int(request.form.get("rating", 0))
            contributions = int(request.form.get("contributions", 0))
            act_num = int(request.form.get("act", END_ACT))
            
            if not name:
                flash("Name is required.", "error")
                return render_template("admin/add_member.html", current_user=current_user, 
                                     start_act=START_ACT, end_act=END_ACT)
            
            # Generate a unique member ID
            member_id = f"member_{act_num}_{len(fetch_data(act_num)) + 1}_{int(datetime.now().timestamp())}"
            
            # Add member to Firestore
            member_data = {
                "Name": name,
                "Rating": rating,
                "Contributions": contributions,
                "DateAdded": datetime.now().isoformat(),
                "AddedBy": current_user.get("username", "Unknown")
            }
            
            # Save to Firestore
            db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).set(member_data)
            
            flash(f"Member '{name}' added successfully to ACT {act_num}!", "success")
            return redirect(url_for("admin_members", act=act_num))
            
        except ValueError as e:
            flash("Please enter valid numbers for rating and contributions.", "error")
        except Exception as e:
            flash(f"Error adding member: {str(e)}", "error")
    
    return render_template("admin/add_member.html", current_user=current_user, 
                         start_act=START_ACT, end_act=END_ACT, default_act=END_ACT)


@app.route("/admin/members/edit/<act_num>/<member_id>", methods=["GET", "POST"])
@admin_required
def admin_edit_member(act_num, member_id):
    current_user = get_current_user()
    act_num = int(act_num)
    
    # Get current member data
    try:
        member_doc = db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).get()
        if not member_doc.exists:
            flash("Member not found.", "error")
            return redirect(url_for("admin_members"))
        member_data = member_doc.to_dict()
    except Exception as e:
        flash("Error retrieving member data.", "error")
        return redirect(url_for("admin_members"))
    
    if request.method == "POST":
        try:
            name = request.form.get("name", "").strip()
            rating = int(request.form.get("rating", 0))
            contributions = int(request.form.get("contributions", 0))
            
            if not name:
                flash("Name is required.", "error")
                return render_template("admin/edit_member.html", current_user=current_user, 
                                     member=member_data, member_id=member_id, act_num=act_num)
            
            # Update member data
            updated_data = {
                "Name": name,
                "Rating": rating,
                "Contributions": contributions,
                "DateAdded": member_data.get("DateAdded", datetime.now().isoformat()),
                "AddedBy": member_data.get("AddedBy", "Unknown"),
                "LastModified": datetime.now().isoformat(),
                "LastModifiedBy": current_user.get("username", "Unknown")
            }
            
            # Update in Firestore
            db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).update(updated_data)
            
            flash(f"Member '{name}' updated successfully!", "success")
            return redirect(url_for("admin_members", act=act_num))
            
        except ValueError as e:
            flash("Please enter valid numbers for rating and contributions.", "error")
        except Exception as e:
            flash(f"Error updating member: {str(e)}", "error")
    
    return render_template("admin/edit_member.html", current_user=current_user, 
                         member=member_data, member_id=member_id, act_num=act_num)


@app.route("/admin/members/delete/<act_num>/<member_id>", methods=["POST"])
@admin_required
def admin_delete_member(act_num, member_id):
    current_user = get_current_user()
    act_num = int(act_num)
    
    try:
        # Get member name for flash message
        member_doc = db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).get()
        member_name = "Unknown"
        if member_doc.exists:
            member_data = member_doc.to_dict()
            member_name = member_data.get("Name", "Unknown")
        
        # Delete member from Firestore
        db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).delete()
        
        flash(f"Member '{member_name}' deleted successfully!", "success")
        
    except Exception as e:
        flash(f"Error deleting member: {str(e)}", "error")
    
    return redirect(url_for("admin_members", act=act_num))


# API Routes for AJAX operations from leaderboard
@app.route("/admin/add_member", methods=["POST"])
@admin_required
def api_add_member():
    current_user = get_current_user()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"})
        
        name = data.get("name", "").strip()
        act_num = int(data.get("act", 1))
        contributions = data.get("contributions", "").strip()
        make_wizard = data.get("makeWizard", False)
        
        # Check if user is 'unknown' account for manual entry privilege
        current_username = current_user.get("username", "").lower()
        is_unknown_account = current_username == "unknown"
        
        # Handle rating assignment
        if is_unknown_account:
            # Unknown account can use either category or manual entry
            category_key = data.get("category")
            manual_rating = data.get("rating")
            
            if category_key and category_key in POINT_CATEGORIES:
                # Use category-based points
                rating = POINT_CATEGORIES[category_key]["points"]
                point_source = f"Category: {POINT_CATEGORIES[category_key]['name']}"
                # Auto-increment contributions when using category
                current_contributions = int(contributions) if contributions.isdigit() else 0
                contributions = str(current_contributions + 1)
            elif manual_rating is not None:
                # Use manual entry for unknown account
                rating = int(manual_rating)
                point_source = "Manual Entry (Admin)"
            else:
                return jsonify({"success": False, "error": "Must select a category or enter manual points"})
        else:
            # All other accounts must use categories only
            category_key = data.get("category")
            if not category_key or category_key not in POINT_CATEGORIES:
                return jsonify({"success": False, "error": "Must select a valid contribution category"})
            
            rating = POINT_CATEGORIES[category_key]["points"]
            point_source = f"Category: {POINT_CATEGORIES[category_key]['name']}"
            # Auto-increment contributions when using category
            current_contributions = int(contributions) if contributions.isdigit() else 0
            contributions = str(current_contributions + 1)
        
        if not name:
            return jsonify({"success": False, "error": "Name is required"})
        
        # Generate a unique member ID
        member_id = f"member_{act_num}_{len(fetch_data(act_num)) + 1}_{int(datetime.now().timestamp())}"
        
        # Add member to Firestore
        member_data = {
            "Name": name,
            "Rating": rating,
            "Contributions": contributions,
            "DateAdded": datetime.now().isoformat(),
            "AddedBy": current_user.get("username", "Unknown"),
            "PointSource": point_source,
            "UpdatedAt": datetime.now().isoformat(),
            "UpdatedBy": current_user.get("username", "Unknown")
        }
        
        # Save to Firestore
        db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).set(member_data)
        
        # Handle Wizard of the Fortnight assignment
        if make_wizard:
            # Create wizard data with expiration tracking
            wizard_data = {
                "wizard_name": name,
                "points": rating,
                "active": True,
                "created_at": datetime.now().isoformat(),
                "created_by": current_user.get("username", "Unknown"),
                "updated_at": datetime.now().isoformat(),
                "updated_by": current_user.get("username", "Unknown"),
                "expires_at": (datetime.now() + timedelta(days=14)).isoformat()  # Auto-calculate expiration
            }
            
            # Save to Firestore
            db.collection('announcements').document('current_wizard').set(wizard_data)
            
            return jsonify({"success": True, "message": f"Member '{name}' added successfully with {point_source} ({rating} points) and selected as Wizard of the Fortnight! (Expires in 14 days)"})
        else:
            return jsonify({"success": True, "message": f"Member '{name}' added successfully with {point_source} ({rating} points)!"})
        
    except ValueError as e:
        return jsonify({"success": False, "error": "Please enter valid numbers for contributions"})
    except Exception as e:
        return jsonify({"success": False, "error": f"Error adding member: {str(e)}"})


@app.route("/admin/edit_member/<int:act_num>/<member_id>", methods=["POST"])
@admin_required
def api_edit_member(act_num, member_id):
    current_user = get_current_user()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"})
        
        # Get current member data
        member_doc = db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).get()
        if not member_doc.exists:
            return jsonify({"success": False, "error": "Member not found"})
        
        member_data = member_doc.to_dict()
        
        name = data.get("name", "").strip()
        contributions = data.get("contributions", "").strip()
        make_wizard = data.get("makeWizard", False)
        
        # Check if user is 'unknown' account for manual entry privilege
        current_username = current_user.get("username", "").lower()
        is_unknown_account = current_username == "unknown"
        
        # Handle rating assignment
        if is_unknown_account:
            # Unknown account can use either category or manual entry
            category_key = data.get("category")
            manual_rating = data.get("rating")
            
            if category_key and category_key in POINT_CATEGORIES:
                # Use category-based points - ADD to existing rating
                current_rating = member_data.get("Rating", 0)
                additional_points = POINT_CATEGORIES[category_key]["points"]
                rating = current_rating + additional_points
                point_source = f"Added {additional_points} pts - {POINT_CATEGORIES[category_key]['name']}"
                # Auto-increment contributions when using category
                current_contributions = int(contributions) if contributions.isdigit() else 0
                contributions = str(current_contributions + 1)
            elif manual_rating is not None:
                # Use manual entry for unknown account - OVERWRITE existing rating
                rating = int(manual_rating)
                point_source = "Manual Entry (Admin Override)"
            else:
                return jsonify({"success": False, "error": "Must select a category or enter manual points"})
        else:
            # All other accounts must use categories only - ADD to existing rating
            category_key = data.get("category")
            if not category_key or category_key not in POINT_CATEGORIES:
                return jsonify({"success": False, "error": "Must select a valid contribution category"})
            
            current_rating = member_data.get("Rating", 0)
            additional_points = POINT_CATEGORIES[category_key]["points"]
            rating = current_rating + additional_points
            point_source = f"Added {additional_points} pts - {POINT_CATEGORIES[category_key]['name']}"
            # Auto-increment contributions when using category
            current_contributions = int(contributions) if contributions.isdigit() else 0
            contributions = str(current_contributions + 1)
        
        if not name:
            return jsonify({"success": False, "error": "Name is required"})
        
        # Update member data
        updated_data = {
            "Name": name,
            "Rating": rating,
            "Contributions": contributions,
            "UpdatedAt": datetime.now().isoformat(),
            "UpdatedBy": current_user.get("username", "Unknown"),
            "PointSource": point_source
        }
        
        # Update in Firestore
        db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).update(updated_data)
        
        # Handle Wizard of the Fortnight assignment
        if make_wizard:
            # Create wizard data with expiration tracking
            wizard_data = {
                "wizard_name": name,
                "points": rating,
                "active": True,
                "created_at": datetime.now().isoformat(),
                "created_by": current_user.get("username", "Unknown"),
                "updated_at": datetime.now().isoformat(),
                "updated_by": current_user.get("username", "Unknown"),
                "expires_at": (datetime.now() + timedelta(days=14)).isoformat()
            }
            
            # Save to Firestore
            db.collection('announcements').document('current_wizard').set(wizard_data)
            
            return jsonify({"success": True, "message": f"Member '{name}' updated successfully with {point_source} ({rating} points) and selected as Wizard of the Fortnight!"})
        else:
            return jsonify({"success": True, "message": f"Member '{name}' updated successfully with {point_source} ({rating} points)!"})
        
    except ValueError as e:
        return jsonify({"success": False, "error": "Please enter valid numbers for contributions"})
    except Exception as e:
        return jsonify({"success": False, "error": f"Error updating member: {str(e)}"})


@app.route("/admin/delete_member/<int:act_num>/<member_id>", methods=["POST"])
@admin_required
def api_delete_member(act_num, member_id):
    current_user = get_current_user()
    
    try:
        # Get member name for response message
        member_doc = db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).get()
        member_name = "Unknown"
        if member_doc.exists:
            member_data = member_doc.to_dict()
            member_name = member_data.get("Name", "Unknown")
        
        # Delete member from Firestore
        db.collection('leaderboard').document(f'act{act_num}').collection('members').document(member_id).delete()
        
        return jsonify({"success": True, "message": f"Member '{member_name}' deleted successfully!"})
        
    except Exception as e:
        return jsonify({"success": False, "error": f"Error deleting member: {str(e)}"})


# API Routes for AJAX operations
@app.route("/api/members/<int:act_num>")
@admin_required
def api_get_members(act_num):
    try:
        members = fetch_data(act_num)
        return jsonify({"success": True, "members": members})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/wizard", methods=["GET", "POST"])
@admin_required
def api_wizard():
    current_user = get_current_user()
    
    if request.method == "GET":
        # Get current Wizard of the Fortnight
        try:
            wizard_doc = db.collection('announcements').document('current_wizard').get()
            if wizard_doc.exists:
                wizard_data = wizard_doc.to_dict()
                
                # Check expiration before returning
                if wizard_data.get("active", False):
                    created_at_str = wizard_data.get("created_at")
                    if created_at_str:
                        try:
                            created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                            if created_at.tzinfo:
                                created_at = created_at.replace(tzinfo=None)
                            
                            days_elapsed = (datetime.now() - created_at).days
                            
                            if days_elapsed >= 14:
                                # Auto-expire
                                wizard_data["active"] = False
                                wizard_data["expired_at"] = datetime.now().isoformat()
                                wizard_data["updated_at"] = datetime.now().isoformat()
                                wizard_data["updated_by"] = "System (Auto-expired)"
                                db.collection('announcements').document('current_wizard').set(wizard_data)
                                return jsonify({"success": True, "wizard": None, "expired": True})
                        except Exception:
                            # If date parsing fails, consider expired
                            wizard_data["active"] = False
                            wizard_data["expired_at"] = datetime.now().isoformat()
                            wizard_data["updated_at"] = datetime.now().isoformat() 
                            wizard_data["updated_by"] = "System (Date parsing failed)"
                            db.collection('announcements').document('current_wizard').set(wizard_data)
                            return jsonify({"success": True, "wizard": None, "expired": True})
                
                return jsonify({"success": True, "wizard": wizard_data if wizard_data.get("active") else None})
            else:
                return jsonify({"success": True, "wizard": None})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})
    
    elif request.method == "POST":
        # Save/Update Wizard of the Fortnight
        try:
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "error": "No data provided"})
            
            remove_wizard = data.get("remove", False)
            
            if remove_wizard:
                # Remove the wizard section completely
                try:
                    db.collection('announcements').document('current_wizard').delete()
                    return jsonify({"success": True, "message": "Wizard of the Fortnight section has been removed."})
                except Exception as e:
                    return jsonify({"success": False, "error": f"Error removing wizard: {str(e)}"})
            else:
                # Set/Update wizard
                wizard_name = data.get("wizard_name", "").strip()
                points = data.get("points", "")
                
                if not wizard_name:
                    return jsonify({"success": False, "error": "Wizard name is required"})
                
                # Create wizard data with expiration tracking
                wizard_data = {
                    "wizard_name": wizard_name,
                    "points": points,
                    "active": True,
                    "created_at": datetime.now().isoformat(),
                    "created_by": current_user.get("username", "Unknown"),
                    "updated_at": datetime.now().isoformat(),
                    "updated_by": current_user.get("username", "Unknown"),
                    "expires_at": (datetime.now() + timedelta(days=14)).isoformat()  # Auto-calculate expiration
                }
                
                # Save to Firestore
                db.collection('announcements').document('current_wizard').set(wizard_data)
                
                return jsonify({"success": True, "message": f"{wizard_name} has been selected as Wizard of the Fortnight! (Expires in 14 days)"})
            
        except Exception as e:
            return jsonify({"success": False, "error": f"Error saving Wizard: {str(e)}"})


if __name__ == "__main__":
    app.run(port=5000, debug=True)
