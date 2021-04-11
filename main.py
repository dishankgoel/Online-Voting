import os
import oauthlib
from flask import Flask, redirect, url_for, render_template, request, current_app, session
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError, TokenExpiredError, OAuth2Error, InvalidClientIdError

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
google_bp = make_google_blueprint(scope=["profile", "email"], redirect_to='login')
app.register_blueprint(google_bp, url_prefix="/login")

import gspread
from oauth2client.service_account import ServiceAccountCredentials

import sqlalchemy

credential = ServiceAccountCredentials.from_json_keyfile_name("credentials.json",
                                                              ["https://spreadsheets.google.com/feeds",                                                               "https://www.googleapis.com/auth/spreadsheets",                                                        "https://www.googleapis.com/auth/drive.file",                                                        "https://www.googleapis.com/auth/drive"])
client = gspread.authorize(credential)
voter_sheet = client.open("voters 2020").sheet1

valid_voters = voter_sheet.batch_get(['G2:G2000'])
valid_voters = valid_voters[0]

def init_connection_engine():
    db_config = {
        # [START cloud_sql_mysql_sqlalchemy_limit]
        # Pool size is the maximum number of permanent connections to keep.
        "pool_size": 5,
        # Temporarily exceeds the set pool_size if no connections are available.
        "max_overflow": 2,
        # The total number of concurrent connections for your application will be
        # a total of pool_size and max_overflow.
        # [END cloud_sql_mysql_sqlalchemy_limit]
        # [START cloud_sql_mysql_sqlalchemy_backoff]
        # SQLAlchemy automatically uses delays between failed connection attempts,
        # but provides no arguments for configuration.
        # [END cloud_sql_mysql_sqlalchemy_backoff]
        # [START cloud_sql_mysql_sqlalchemy_timeout]
        # 'pool_timeout' is the maximum number of seconds to wait when retrieving a
        # new connection from the pool. After the specified amount of time, an
        # exception will be thrown.
        "pool_timeout": 30,  # 30 seconds
        # [END cloud_sql_mysql_sqlalchemy_timeout]
        # [START cloud_sql_mysql_sqlalchemy_lifetime]
        # 'pool_recycle' is the maximum number of seconds a connection can persist.
        # Connections that live longer than the specified amount of time will be
        # reestablished
        "pool_recycle": 1800,  # 30 minutes
        # [END cloud_sql_mysql_sqlalchemy_lifetime]
    }

    if os.environ.get("DB_HOST"):
        return init_tcp_connection_engine(db_config)
    else:
        return init_unix_connection_engine(db_config)


def init_tcp_connection_engine(db_config):
    # [START cloud_sql_mysql_sqlalchemy_create_tcp]
    # Remember - storing secrets in plaintext is potentially unsafe. Consider using
    # something like https://cloud.google.com/secret-manager/docs/overview to help keep
    # secrets secret.
    db_user = os.environ["DB_USER"]
    db_pass = os.environ["DB_PASS"]
    db_name = os.environ["DB_NAME"]
    db_host = os.environ["DB_HOST"]

    # Extract host and port from db_host
    host_args = db_host.split(":")
    db_hostname, db_port = host_args[0], int(host_args[1])

    pool = sqlalchemy.create_engine(
        # Equivalent URL:
        # mysql+pymysql://<db_user>:<db_pass>@<db_host>:<db_port>/<db_name>
        sqlalchemy.engine.url.URL(
            drivername="mysql+pymysql",
            username=db_user,  # e.g. "my-database-user"
            password=db_pass,  # e.g. "my-database-password"
            host=db_hostname,  # e.g. "127.0.0.1"
            port=db_port,  # e.g. 3306
            database=db_name,  # e.g. "my-database-name"
        ),
        # ... Specify additional properties here.
        # [END cloud_sql_mysql_sqlalchemy_create_tcp]
        **db_config
        # [START cloud_sql_mysql_sqlalchemy_create_tcp]
    )
    # [END cloud_sql_mysql_sqlalchemy_create_tcp]

    return pool


def init_unix_connection_engine(db_config):
    # [START cloud_sql_mysql_sqlalchemy_create_socket]
    # Remember - storing secrets in plaintext is potentially unsafe. Consider using
    # something like https://cloud.google.com/secret-manager/docs/overview to help keep
    # secrets secret.
    db_user = os.environ["DB_USER"]
    db_pass = os.environ["DB_PASS"]
    db_name = os.environ["DB_NAME"]
    db_socket_dir = os.environ.get("DB_SOCKET_DIR", "/cloudsql")
    cloud_sql_connection_name = os.environ["CLOUD_SQL_CONNECTION_NAME"]

    pool = sqlalchemy.create_engine(
        # Equivalent URL:
        # mysql+pymysql://<db_user>:<db_pass>@/<db_name>?unix_socket=<socket_path>/<cloud_sql_instance_name>
        sqlalchemy.engine.url.URL(
            drivername="mysql+pymysql",
            username=db_user,  # e.g. "my-database-user"
            password=db_pass,  # e.g. "my-database-password"
            database=db_name,  # e.g. "my-database-name"
            query={
                "unix_socket": "{}/{}".format(
                    db_socket_dir,  # e.g. "/cloudsql"
                    cloud_sql_connection_name)  # i.e "<PROJECT-NAME>:<INSTANCE-REGION>:<INSTANCE-NAME>"
            }
        ),
        # ... Specify additional properties here.

        # [END cloud_sql_mysql_sqlalchemy_create_socket]
        **db_config
        # [START cloud_sql_mysql_sqlalchemy_create_socket]
    )
    # [END cloud_sql_mysql_sqlalchemy_create_socket]

    return pool


# The SQLAlchemy engine will help manage interactions, including automatically
# managing a pool of connections to your database
db = init_connection_engine()


def validate_voter(email_id):
    if([email_id] in valid_voters):
        return True
    else:
        return False


def check_repeat(email_id):
    with db.connect() as conn:
        emails = conn.execute("SELECT email from done").fetchall()
    if((email_id, ) in emails):
        return -1
    else:
        return len(email_id)

def update_votes(vote, email_id, ip):
    p1 = [0, 0, 0, 0]
    p2 = [0,0,0]
    p3 = [0,0,0]
    p4 = [0,0]
    p5 = [0,0]
    p6 = [0,0]
    p7 = [0,0]
    p8 = [0,0]
    p1[vote[0]] = 1
    p2[vote[1]] = 1
    p3[vote[2]] = 1
    p4[vote[3]] = 1
    p5[vote[4]] = 1
    p6[vote[5]] = 1
    p7[vote[6]] = 1
    p8[vote[7]] = 1
    update_vote = sqlalchemy.text("INSERT INTO tally values (:vyom , :jainam , :ujjwal , :gsec_nota , :shivang , :sudhir , :wsecy_nota , :shantanu , :aditya , :asecy_nota , :kanishk , :tsecy_nota , :vala , :ssecy_nota , :nishant , :csecy_nota , :mohit , :psecy_nota , :kaushik , :isecy_nota )")
    update_email = sqlalchemy.text("INSERT INTO done values (:email, :ip)")
    try:
        with db.connect() as conn:
            conn.execute(update_vote, vyom = p1[0] , jainam = p1[1] , ujjwal = p1[2] , gsec_nota = p1[3] , shivang = p2[0] , sudhir = p2[1] , wsecy_nota = p2[2] , shantanu = p3[0] , aditya = p3[1] , asecy_nota = p3[2] , kanishk = p4[0] , tsecy_nota = p4[1] , vala = p5[0] , ssecy_nota = p5[1] , nishant = p6[0] , csecy_nota = p6[1] , mohit = p7[0] , psecy_nota = p7[1] , kaushik = p8[0] , isecy_nota = p8[1])
            conn.execute(update_email, email = email_id, ip = ip)
    except:
        return -1


def get_email():
    if google.authorized:
        resp = google.get("/oauth2/v1/userinfo")
        # assert resp.ok, resp.text
        email_id = resp.json()["email"]
        return email_id
    else:
        return "User not logged in"

def logout():
    """
    This endpoint tries to revoke the token
    and then it clears the session
    """
    if google.authorized:
        try:
            google.get(
                'https://accounts.google.com/o/oauth2/revoke',
                params={
                    'token':
                        current_app.blueprints['google'].token['access_token']},
            )
        except TokenExpiredError:
            pass
        except InvalidClientIdError:
            # Our OAuth session apparently expired. We could renew the token
            # and logout again but that seems a bit silly, so for now fake
            # it.
            pass
    _empty_session()
    return redirect(url_for('index'))


def _empty_session():
    """
    Deletes the google token and clears the session
    """
    if 'google' in current_app.blueprints and hasattr(current_app.blueprints['google'], 'token'):
        del current_app.blueprints['google'].token
    session.clear()


@app.errorhandler(oauthlib.oauth2.rfc6749.errors.TokenExpiredError)
@app.errorhandler(oauthlib.oauth2.rfc6749.errors.InvalidClientIdError)
def token_expired(_):
    _empty_session()
    return redirect(url_for('index'))

@app.route("/")
def index():
    if google.authorized:
        logout()
    return render_template('index.html')


@app.route("/google_login")
def login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    
    try:
        resp = google.get("/oauth2/v1/userinfo")
        assert resp.ok, resp.text
    except (InvalidGrantError, TokenExpiredError) as e:  # or maybe any OAuth2Error
        return redirect(url_for("google.login"))

    email_id = get_email()
    if(check_repeat(email_id) == -1):
        logout()
        return render_template('log.html', message = 'You have already voted in the Student Council 2020 Elections.')
    elif(validate_voter(email_id) == False):
        logout()
        return render_template('log.html', message = 'You are not authorized to vote with the given Email ID. Please make sure you are using your IIT Gn Email ID for voting.')
    else:
        return redirect(url_for('vote'))

@app.route("/vote")
def vote():
    if not google.authorized:
        return redirect(url_for('index'))
    else:   
        return render_template('vote.html')

@app.route("/process_vote", methods=['POST'])
def process_vote():
    if( request.method == 'POST'):
        if not google.authorized:
            return redirect(url_for('index'))
        else:
            try:
                resp = google.get("/oauth2/v1/userinfo")
                assert resp.ok, resp.text
            except (InvalidGrantError, TokenExpiredError) as e:  # or maybe any OAuth2Error
                return render_template('log.html', message = 'Session Expired. Please vote again by going to <a href="https://iitgn-online-voting.el.r.appspot.com/">https://iitgn-online-voting.el.r.appspot.com/</a>')
            email_id = get_email()
            valid = check_repeat(email_id)
            if(valid == -1):
                logout()
                return render_template('log.html', message = 'You have already voted in the Student Council 2020 Elections.')
            elif(validate_voter(email_id) == False):
                logout()
                return render_template('log.html', message = 'You are not authorized to vote with the given Email ID. Please make sure you are using your IIT Gn Email ID for voting.')
            else:
                try:
                    ip = request.headers['X-AppEngine-User-IP']
                    gsecy = request.form['gsecy']
                    wsecy = request.form['wsecy']
                    asecy = request.form['asecy']
                    tsecy = request.form['tsecy']
                    ssecy = request.form['ssecy']
                    csecy = request.form['csecy']
                    psecy = request.form['psecy']
                    irpsecy = request.form['isecy']
                    vote = [int(gsecy), int(wsecy), int(asecy), int(tsecy), int(ssecy), int(csecy), int(psecy), int(irpsecy)]
                    result = update_votes(vote, email_id, ip)
                    if(result == -1):
                        return render_template('log.html', message = "Something went wrong. Please vote again in some time.")
                except Exception as e:
                    print(e)
                    logout()
                    return render_template('log.html', message = "Something went wrong. Please vote again in some time.")
                
                logout()
                return render_template('success.html')

@app.route('/sdjkgbgekjgb3t34t34utgetvotes')
def see_votes():
    with db.connect() as conn:
        votes = conn.execute("SELECT * from tally").fetchall()
    p1 = [0, 0, 0, 0]
    p2 = [0,0,0]
    p3 = [0,0,0]
    p4 = [0,0]
    p5 = [0,0]
    p6 = [0,0]
    p7 = [0,0]
    p8 = [0,0]
    for i in votes:
        p1[0] += i[0]
        p1[1] += i[1]
        p1[2] += i[2]
        p1[3] += i[3]
        p2[0] += i[4]
        p2[1] += i[5]
        p2[2] += i[6]
        p3[0] += i[7]
        p3[1] += i[8]
        p3[2] += i[9]
        p4[0] += i[10]
        p4[1] += i[11]
        p5[0] += i[12]
        p5[1] += i[13]
        p6[0] += i[14]
        p6[1] += i[15]
        p7[0] += i[16]
        p7[1] += i[17]
        p8[0] += i[18]
        p8[1] += i[19]

    return render_template('tally.html', vyom = p1[0] , jainam = p1[1] , ujjwal = p1[2] , gsec_nota = p1[3] , shivang = p2[0] , sudhir = p2[1] , wsecy_nota = p2[2] , shantanu = p3[0] , aditya = p3[1] , asecy_nota = p3[2] , kanishk = p4[0] , tsecy_nota = p4[1] , vala = p5[0] , ssecy_nota = p5[1] , nishant = p6[0] , csecy_nota = p6[1] , mohit = p7[0] , psecy_nota = p7[1] , kaushik = p8[0] , isecy_nota = p8[1])

debug
@app.route('/v')
def v():
    return render_template('vote.html')

@app.route('/l')
def success():
    return render_template('finish.html')

# @app.route('/log')
# def log():
#     return render_template('log.html', message = 'Session Expired. Please vote again by going to <a href="https://iitgn-online-voting.el.r.appspot.com/">https://iitgn-online-voting.el.r.appspot.com/</a>')
#     return render_template('log.html', message = 'You have already voted in the Student Council 2020 Elections')
#     return render_template('log.html', message = 'You are not authorized to vote with the given Email ID. Please make sure you are using your IIT Gn Email ID for voting')



@app.route("/_ah/warmup")
def warmup():
    return '', 200, {}




