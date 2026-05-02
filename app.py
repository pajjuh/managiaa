import os
import re
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import (Flask, abort, flash, redirect, render_template, request, session,
                   url_for, send_from_directory, jsonify)
from supabase import create_client, Client
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'png', 'jpg', 'jpeg', 'txt', 'zip'}

# --- Supabase Client ---
supabase: Client = create_client(
    os.getenv('SUPABASE_URL'),
    os.getenv('SUPABASE_KEY')
)


# --- Helpers ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def scoped_table(table, columns='*'):
    """Returns query builder filtered by active org. Supports chaining filters/ordering."""
    return supabase.table(table).select(columns).eq('organization_id', session['active_org_id'])


def scoped_insert(table, data):
    """Auto-stamps organization_id on every insert."""
    data['organization_id'] = session['active_org_id']
    return supabase.table(table).insert(data).execute()


def ensure_org_access(table, record_id):
    """Verify record belongs to active org. Aborts 403 if not."""
    res = supabase.table(table).select('organization_id').eq('id', record_id).execute()
    if not res.data or res.data[0]['organization_id'] != session['active_org_id']:
        abort(403)


def get_user_role_from_db(user_id, org_id):
    """DB-verified role for critical/destructive actions."""
    res = supabase.table('memberships').select('role').eq('user_id', user_id).eq('organization_id', org_id).execute()
    return res.data[0]['role'] if res.data else None


def generate_slug(name):
    """Generate URL-safe slug with uniqueness handling."""
    base_slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
    slug = base_slug
    counter = 1
    while supabase.table('organizations').select('id').eq('slug', slug).execute().data:
        counter += 1
        slug = f"{base_slug}-{counter}"
    return slug


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def org_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        if session.get('org_role') not in ('owner', 'admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


def is_org_admin():
    return session.get('org_role') in ('owner', 'admin')


def log_audit(user_id, action, entity_type, entity_id=None, details=None):
    try:
        data = {
            'user_id': user_id,
            'action': action,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'details': details,
            'organization_id': session.get('active_org_id')
        }
        supabase.table('audit_log').insert(data).execute()
    except Exception:
        pass


def get_org_users():
    """Get all users in the current org via memberships."""
    memberships = scoped_table('memberships', 'user_id, role').execute().data or []
    if not memberships:
        return [], {}
    user_ids = [m['user_id'] for m in memberships]
    users = supabase.table('users').select('*').in_('id', user_ids).execute().data or []
    role_map = {m['user_id']: m['role'] for m in memberships}
    for u in users:
        u['org_role'] = role_map.get(u['id'], 'member')
    return users, {u['id']: u['full_name'] for u in users}


@app.context_processor
def inject_globals():
    user = None
    current_org = None
    if 'user_id' in session:
        res = supabase.table('users').select('*').eq('id', session['user_id']).execute()
        if res.data:
            user = res.data[0]
        if 'active_org_id' in session:
            current_org = {
                'id': session['active_org_id'],
                'name': session.get('org_name', ''),
                'role': session.get('org_role', 'member')
            }
    return dict(current_user=user, current_org=current_org, now=datetime.now())


# ============================================================
# AUTH ROUTES
# ============================================================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Please fill in all fields.', 'danger')
            return render_template('auth/login.html')
        res = supabase.table('users').select('*').eq('username', username).execute()
        if res.data and check_password_hash(res.data[0]['password_hash'], password):
            user = res.data[0]
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            # Load memberships
            memberships = supabase.table('memberships').select('organization_id, role').eq('user_id', user['id']).execute().data or []
            if not memberships:
                flash(f'Welcome, {user["full_name"]}!', 'success')
                return redirect(url_for('onboarding'))
            m = memberships[0]
            session['active_org_id'] = m['organization_id']
            session['org_role'] = m['role']
            org = supabase.table('organizations').select('name').eq('id', m['organization_id']).execute().data
            session['org_name'] = org[0]['name'] if org else ''
            flash(f'Welcome back, {user["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        company_name = request.form.get('company_name', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not all([username, email, full_name, password, confirm]):
            flash('Please fill in all fields.', 'danger')
            return render_template('auth/register.html')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')
        if len(password) < 4:
            flash('Password must be at least 4 characters.', 'danger')
            return render_template('auth/register.html')
        existing = supabase.table('users').select('id').eq('username', username).execute()
        if existing.data:
            flash('Username already taken.', 'danger')
            return render_template('auth/register.html')
        existing = supabase.table('users').select('id').eq('email', email).execute()
        if existing.data:
            flash('Email already registered.', 'danger')
            return render_template('auth/register.html')
        # Create user
        user_res = supabase.table('users').insert({
            'username': username,
            'email': email,
            'full_name': full_name,
            'password_hash': generate_password_hash(password),
            'role': 'user'
        }).execute()
        new_user = user_res.data[0]
        # If company name provided, create org + membership
        if company_name:
            slug = generate_slug(company_name)
            try:
                org_res = supabase.table('organizations').insert({
                    'name': company_name,
                    'slug': slug
                }).execute()
                org_id = org_res.data[0]['id']
                supabase.table('memberships').insert({
                    'user_id': new_user['id'],
                    'organization_id': org_id,
                    'role': 'owner'
                }).execute()
            except Exception:
                slug = generate_slug(company_name)
                org_res = supabase.table('organizations').insert({
                    'name': company_name,
                    'slug': slug
                }).execute()
                org_id = org_res.data[0]['id']
                supabase.table('memberships').insert({
                    'user_id': new_user['id'],
                    'organization_id': org_id,
                    'role': 'owner'
                }).execute()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html')


@app.route('/onboarding', methods=['GET', 'POST'])
@login_required
def onboarding():
    # If user already has an org, redirect to dashboard
    memberships = supabase.table('memberships').select('organization_id').eq('user_id', session['user_id']).execute().data or []
    if memberships:
        m = memberships[0]
        session['active_org_id'] = m['organization_id']
        org = supabase.table('organizations').select('name').eq('id', m['organization_id']).execute().data
        session['org_name'] = org[0]['name'] if org else ''
        role = supabase.table('memberships').select('role').eq('user_id', session['user_id']).eq('organization_id', m['organization_id']).execute().data
        session['org_role'] = role[0]['role'] if role else 'member'
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        company_name = request.form.get('company_name', '').strip()
        if not company_name:
            flash('Company name is required.', 'danger')
            return render_template('auth/onboarding.html')
        slug = generate_slug(company_name)
        org_res = supabase.table('organizations').insert({
            'name': company_name,
            'slug': slug
        }).execute()
        org_id = org_res.data[0]['id']
        supabase.table('memberships').insert({
            'user_id': session['user_id'],
            'organization_id': org_id,
            'role': 'owner'
        }).execute()
        session['active_org_id'] = org_id
        session['org_role'] = 'owner'
        session['org_name'] = company_name
        flash(f'Organization "{company_name}" created!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('auth/onboarding.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


# ============================================================
# DASHBOARD
# ============================================================
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    role = session.get('org_role', 'member')

    all_users, user_map = get_org_users()
    tasks = scoped_table('tasks').execute().data or []
    projects = scoped_table('projects').execute().data or []

    if role == 'member':
        tasks = [t for t in tasks if t.get('assigned_to') == user_id]

    total = len(tasks)
    completed = len([t for t in tasks if t['status'] == 'completed'])
    in_progress = len([t for t in tasks if t['status'] == 'in-progress'])
    pending = len([t for t in tasks if t['status'] == 'pending'])
    high_priority = len([t for t in tasks if t['priority'] == 'high'])
    overdue = len([t for t in tasks if t.get('due_date') and t['due_date'] < datetime.now().strftime('%Y-%m-%d') and t['status'] != 'completed'])

    recent_tasks = sorted(tasks, key=lambda x: x.get('created_at', ''), reverse=True)[:5]

    return render_template('dashboard.html',
                           total=total, completed=completed,
                           in_progress=in_progress, pending=pending,
                           high_priority=high_priority, overdue=overdue,
                           recent_tasks=recent_tasks, user_map=user_map,
                           projects=projects, all_users=all_users,
                           tasks=tasks)


# ============================================================
# TASKS
# ============================================================
@app.route('/tasks')
@login_required
def task_list():
    role = session.get('org_role', 'member')
    user_id = session['user_id']

    status_filter = request.args.get('status', '')
    priority_filter = request.args.get('priority', '')
    project_filter = request.args.get('project', '')
    search_q = request.args.get('q', '').strip()
    sort_by = request.args.get('sort', 'created_at')
    sort_dir = request.args.get('dir', 'desc')
    page = int(request.args.get('page', 1))
    per_page = 10

    query = scoped_table('tasks')
    if role == 'member':
        query = query.eq('assigned_to', user_id)
    if status_filter:
        query = query.eq('status', status_filter)
    if priority_filter:
        query = query.eq('priority', priority_filter)
    if project_filter:
        query = query.eq('project_id', int(project_filter))
    if search_q:
        query = query.ilike('title', f'%{search_q}%')

    ascending = sort_dir == 'asc'
    query = query.order(sort_by, desc=not ascending)

    all_results = query.execute().data or []
    total_count = len(all_results)
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    tasks = all_results[(page - 1) * per_page: page * per_page]

    projects = scoped_table('projects', 'id,name').execute().data or []
    all_users, user_map = get_org_users()
    project_map = {p['id']: p['name'] for p in projects}

    return render_template('tasks/list.html', tasks=tasks, projects=projects,
                           users=all_users, user_map=user_map, project_map=project_map,
                           status_filter=status_filter, priority_filter=priority_filter,
                           project_filter=project_filter, search_q=search_q,
                           sort_by=sort_by, sort_dir=sort_dir,
                           page=page, total_pages=total_pages, total_count=total_count)


@app.route('/tasks/create', methods=['GET', 'POST'])
@login_required
def task_create():
    user_id = session['user_id']
    projects = scoped_table('projects', 'id,name').eq('status', 'active').execute().data or []
    all_users, _ = get_org_users()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        priority = request.form.get('priority', 'medium')
        status = request.form.get('status', 'pending')
        due_date = request.form.get('due_date') or None
        project_id = request.form.get('project_id')
        assigned_to = request.form.get('assigned_to')

        if not title:
            flash('Task title is required.', 'danger')
            return render_template('tasks/create.html', projects=projects, users=all_users)

        data = {
            'title': title,
            'description': description,
            'priority': priority,
            'status': status,
            'due_date': due_date,
            'project_id': int(project_id) if project_id else None,
            'assigned_to': int(assigned_to) if assigned_to else None,
            'created_by': user_id
        }
        res = scoped_insert('tasks', data)
        log_audit(session['user_id'], 'created', 'task', res.data[0]['id'] if res.data else None, f'Created task: {title}')
        flash('Task created successfully!', 'success')
        return redirect(url_for('task_list'))
    return render_template('tasks/create.html', projects=projects, users=all_users)


@app.route('/tasks/<int:task_id>')
@login_required
def task_detail(task_id):
    ensure_org_access('tasks', task_id)
    res = supabase.table('tasks').select('*').eq('id', task_id).execute()
    task = res.data[0]

    comments = supabase.table('comments').select('*').eq('task_id', task_id).order('created_at', desc=False).execute().data or []
    attachments = supabase.table('attachments').select('*').eq('task_id', task_id).order('uploaded_at', desc=True).execute().data or []
    all_users, _ = get_org_users()
    user_map = {u['id']: u for u in all_users}
    projects = scoped_table('projects', 'id,name').execute().data or []
    project_map = {p['id']: p['name'] for p in projects}

    return render_template('tasks/detail.html', task=task, comments=comments,
                           attachments=attachments, user_map=user_map,
                           project_map=project_map, users=all_users, projects=projects)


@app.route('/tasks/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def task_edit(task_id):
    ensure_org_access('tasks', task_id)
    res = supabase.table('tasks').select('*').eq('id', task_id).execute()
    task = res.data[0]

    projects = scoped_table('projects', 'id,name').eq('status', 'active').execute().data or []
    all_users, _ = get_org_users()

    if request.method == 'POST':
        data = {
            'title': request.form.get('title', '').strip(),
            'description': request.form.get('description', '').strip(),
            'priority': request.form.get('priority', 'medium'),
            'status': request.form.get('status', 'pending'),
            'due_date': request.form.get('due_date') or None,
            'project_id': int(request.form.get('project_id')) if request.form.get('project_id') else None,
            'assigned_to': int(request.form.get('assigned_to')) if request.form.get('assigned_to') else None,
            'updated_at': datetime.now().isoformat()
        }
        if not data['title']:
            flash('Task title is required.', 'danger')
            return render_template('tasks/create.html', task=task, projects=projects, users=all_users, editing=True)
        supabase.table('tasks').update(data).eq('id', task_id).execute()
        log_audit(session['user_id'], 'updated', 'task', task_id, f'Updated task: {data["title"]}')
        flash('Task updated successfully!', 'success')
        return redirect(url_for('task_detail', task_id=task_id))
    return render_template('tasks/create.html', task=task, projects=projects, users=all_users, editing=True)


@app.route('/tasks/<int:task_id>/status', methods=['POST'])
@login_required
def task_status_update(task_id):
    ensure_org_access('tasks', task_id)
    new_status = request.form.get('status')
    if new_status in ('pending', 'in-progress', 'completed'):
        supabase.table('tasks').update({'status': new_status, 'updated_at': datetime.now().isoformat()}).eq('id', task_id).execute()
        log_audit(session['user_id'], 'status_changed', 'task', task_id, f'Status → {new_status}')
        flash(f'Task status updated to {new_status}.', 'success')
    return redirect(request.referrer or url_for('task_list'))


@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def task_delete(task_id):
    ensure_org_access('tasks', task_id)
    supabase.table('tasks').delete().eq('id', task_id).execute()
    log_audit(session['user_id'], 'deleted', 'task', task_id, 'Deleted task')
    flash('Task deleted.', 'info')
    return redirect(url_for('task_list'))


@app.route('/tasks/<int:task_id>/comment', methods=['POST'])
@login_required
def task_comment(task_id):
    ensure_org_access('tasks', task_id)
    content = request.form.get('content', '').strip()
    if content:
        scoped_insert('comments', {
            'task_id': task_id,
            'user_id': session['user_id'],
            'content': content
        })
        flash('Comment added.', 'success')
    return redirect(url_for('task_detail', task_id=task_id))


@app.route('/tasks/<int:task_id>/upload', methods=['POST'])
@login_required
def task_upload(task_id):
    if 'file' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('task_detail', task_id=task_id))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('task_detail', task_id=task_id))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        safe_name = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
        file.save(filepath)
        supabase.table('attachments').insert({
            'task_id': task_id,
            'user_id': session['user_id'],
            'filename': filename,
            'filepath': safe_name
        }).execute()
        flash('File uploaded successfully!', 'success')
    else:
        flash('File type not allowed.', 'danger')
    return redirect(url_for('task_detail', task_id=task_id))


@app.route('/uploads/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ============================================================
# PROJECTS
# ============================================================
@app.route('/projects')
@login_required
def project_list():
    projects = scoped_table('projects').order('created_at', desc=True).execute().data or []
    tasks = scoped_table('tasks', 'id,project_id,status').execute().data or []
    all_users, user_map = get_org_users()

    for p in projects:
        p_tasks = [t for t in tasks if t.get('project_id') == p['id']]
        p['total_tasks'] = len(p_tasks)
        p['completed_tasks'] = len([t for t in p_tasks if t['status'] == 'completed'])
        p['progress'] = int((p['completed_tasks'] / p['total_tasks'] * 100)) if p['total_tasks'] > 0 else 0

    return render_template('projects/list.html', projects=projects, user_map=user_map)


@app.route('/projects/create', methods=['GET', 'POST'])
@org_admin_required
def project_create():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        if not name:
            flash('Project name is required.', 'danger')
            return render_template('projects/create.html')
        res = scoped_insert('projects', {
            'name': name,
            'description': description,
            'created_by': session['user_id']
        })
        log_audit(session['user_id'], 'created', 'project', res.data[0]['id'] if res.data else None, f'Created project: {name}')
        flash('Project created!', 'success')
        return redirect(url_for('project_list'))
    return render_template('projects/create.html')


@app.route('/projects/<int:project_id>')
@login_required
def project_detail(project_id):
    ensure_org_access('projects', project_id)
    res = supabase.table('projects').select('*').eq('id', project_id).execute()
    project = res.data[0]

    tasks = scoped_table('tasks').eq('project_id', project_id).order('created_at', desc=True).execute().data or []
    members = scoped_table('project_members').eq('project_id', project_id).execute().data or []
    all_users, _ = get_org_users()
    user_map = {u['id']: u for u in all_users}
    member_ids = [m['user_id'] for m in members]

    total = len(tasks)
    completed = len([t for t in tasks if t['status'] == 'completed'])
    progress = int(completed / total * 100) if total > 0 else 0

    return render_template('projects/detail.html', project=project, tasks=tasks,
                           members=members, users=all_users, user_map=user_map,
                           member_ids=member_ids, total=total, completed=completed, progress=progress)


@app.route('/projects/<int:project_id>/edit', methods=['GET', 'POST'])
@org_admin_required
def project_edit(project_id):
    ensure_org_access('projects', project_id)
    res = supabase.table('projects').select('*').eq('id', project_id).execute()
    project = res.data[0]
    if request.method == 'POST':
        data = {
            'name': request.form.get('name', '').strip(),
            'description': request.form.get('description', '').strip(),
            'status': request.form.get('status', 'active')
        }
        supabase.table('projects').update(data).eq('id', project_id).execute()
        log_audit(session['user_id'], 'updated', 'project', project_id, f'Updated project: {data["name"]}')
        flash('Project updated!', 'success')
        return redirect(url_for('project_detail', project_id=project_id))
    return render_template('projects/create.html', project=project, editing=True)


@app.route('/projects/<int:project_id>/add_member', methods=['POST'])
@org_admin_required
def project_add_member(project_id):
    ensure_org_access('projects', project_id)
    user_id = request.form.get('user_id')
    if user_id:
        try:
            scoped_insert('project_members', {
                'project_id': project_id,
                'user_id': int(user_id)
            })
            flash('Member added to project.', 'success')
        except Exception:
            flash('Member already in project.', 'warning')
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/projects/<int:project_id>/remove_member/<int:user_id>', methods=['POST'])
@org_admin_required
def project_remove_member(project_id, user_id):
    ensure_org_access('projects', project_id)
    supabase.table('project_members').delete().eq('project_id', project_id).eq('user_id', user_id).execute()
    flash('Member removed from project.', 'info')
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@org_admin_required
def project_delete(project_id):
    ensure_org_access('projects', project_id)
    supabase.table('projects').delete().eq('id', project_id).execute()
    log_audit(session['user_id'], 'deleted', 'project', project_id, 'Deleted project')
    flash('Project deleted.', 'info')
    return redirect(url_for('project_list'))


# ============================================================
# MEMBERS
# ============================================================
@app.route('/members')
@org_admin_required
def member_list():
    all_users, _ = get_org_users()
    tasks = scoped_table('tasks', 'id,assigned_to,status').execute().data or []
    for u in all_users:
        u_tasks = [t for t in tasks if t.get('assigned_to') == u['id']]
        u['total_tasks'] = len(u_tasks)
        u['completed_tasks'] = len([t for t in u_tasks if t['status'] == 'completed'])
    return render_template('members/list.html', users=all_users)


@app.route('/members/<int:user_id>/role', methods=['POST'])
@org_admin_required
def member_role(user_id):
    new_role = request.form.get('role')
    if new_role in ('owner', 'admin', 'member'):
        # DB-verify caller is owner/admin
        caller_role = get_user_role_from_db(session['user_id'], session['active_org_id'])
        if caller_role not in ('owner', 'admin'):
            flash('Permission denied.', 'danger')
            return redirect(url_for('member_list'))
        if new_role == 'owner' and caller_role != 'owner':
            flash('Only the owner can transfer ownership.', 'danger')
            return redirect(url_for('member_list'))
        supabase.table('memberships').update({'role': new_role}).eq('user_id', user_id).eq('organization_id', session['active_org_id']).execute()
        flash(f'Role updated to {new_role}.', 'success')
    return redirect(url_for('member_list'))


@app.route('/members/add', methods=['POST'])
@org_admin_required
def member_add():
    """Admin creates a new user and adds them to the current org."""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    full_name = request.form.get('full_name', '').strip()
    password = request.form.get('password', '')
    if not all([username, email, full_name, password]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('member_list'))
    existing = supabase.table('users').select('id').eq('username', username).execute()
    if existing.data:
        flash('Username already taken.', 'danger')
        return redirect(url_for('member_list'))
    user_res = supabase.table('users').insert({
        'username': username, 'email': email, 'full_name': full_name,
        'password_hash': generate_password_hash(password), 'role': 'user'
    }).execute()
    new_user = user_res.data[0]
    supabase.table('memberships').insert({
        'user_id': new_user['id'],
        'organization_id': session['active_org_id'],
        'role': 'member'
    }).execute()
    flash(f'Member {full_name} added!', 'success')
    return redirect(url_for('member_list'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session['user_id']
    res = supabase.table('users').select('*').eq('id', user_id).execute()
    user = res.data[0] if res.data else None
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        new_password = request.form.get('new_password', '')
        data = {}
        if full_name:
            data['full_name'] = full_name
            session['full_name'] = full_name
        if email:
            data['email'] = email
        if new_password and len(new_password) >= 4:
            data['password_hash'] = generate_password_hash(new_password)
        if data:
            supabase.table('users').update(data).eq('id', user_id).execute()
            flash('Profile updated!', 'success')
        return redirect(url_for('profile'))

    my_tasks = scoped_table('tasks').eq('assigned_to', user_id).order('created_at', desc=True).execute().data or []
    return render_template('members/profile.html', user=user, my_tasks=my_tasks)


# ============================================================
# AUDIT LOG
# ============================================================
@app.route('/audit')
@org_admin_required
def audit_log_view():
    logs = scoped_table('audit_log').order('timestamp', desc=True).limit(100).execute().data or []
    all_users, user_map = get_org_users()
    return render_template('audit.html', logs=logs, user_map=user_map)


# ============================================================
# ERROR HANDLERS
# ============================================================
@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
