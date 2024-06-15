import reflex as rx

import re

import hashlib
import os

from rxconfig import config


#this class is used to create DB

from sqlmodel import Field, SQLModel, create_engine, Session,select

class User(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    full_name: str
    mobile_number: str
    email: str
    password: str
    salt: str

# Define the database URL and create the engine
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL)

# Create the database tables
SQLModel.metadata.create_all(engine)




############################################################

class State(rx.State):
    
    full_name: str = ""
    mobile_number: str = ""
    mobile_error_message: str = ""
    email: str = ""
    email_error_message: str = ""
    password: str = ""
    confirm_password: str = ""
    password_error_message: str = ""
    error_message: str = ""

    email_log: str = ""
    password_log: str = ""
    error_message_log: str = ""

    email_forget: str = ""
    email_verified: bool = False
    reset_error_message: str = ""


    password_set: str = ""
    confirm_password_set: str = ""
    error_message_set: str = ""
    password_set_error_message: str = ""

    logged_in_email: str = ""
    logged_in_name: str =""


    #functions for storing entered details

    def set_full_name(self, value: str):
        self.full_name = value

    def set_mobile_number(self, value: str):
        self.mobile_number = value
        self.validate_mobile_number()


    def set_email(self, value: str):
        self.email = value
        self.validate_email()

    def set_password(self, value: str):
        self.password = value



    def validate_password(self):
        password_pattern = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'
        if not re.match(password_pattern, self.password):
            self.password_error_message = "Password must be at least 8 characters long and contain both letters and numbers."
            return False
        else:
            self.password_error_message = ""
            return True

    def validate_email(self):
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, self.email):
            self.email_error_message = "Invalid email format. Must be sometext@mail.com."
        else:
            self.email_error_message = ""

    def validate_mobile_number(self):
        if len(self.mobile_number) != 10 or not self.mobile_number.isdigit():
            self.mobile_error_message = "Mobile number must be exactly 10 digits."
        else:
            self.mobile_error_message = ""

############functions used for hashing#################################################3

    def hash_password(self, password: str, salt: str) -> str:
        return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

    def generate_salt(self) -> str:
        return os.urandom(16).hex()

    def handle_signup_submit(self):
        self.validate_mobile_number()
        self.validate_email()
        password_check = self.validate_password()
        if password_check:
            if not self.full_name or not self.mobile_number or not self.email or not self.password:
                self.error_message = "Please enter all the details"
                return
            if self.mobile_error_message:
                return
            
            salt = self.generate_salt()
            hashed_password = self.hash_password(self.password, salt)

            with Session(engine) as session:
                    new_user = User(
                        full_name=self.full_name,
                        mobile_number=self.mobile_number,
                        email=self.email,
                        password=hashed_password,
                        salt=salt,
                    )
                    session.add(new_user)
                    session.commit()
                    session.refresh(new_user)

            self.error_message = "Signup successful!"
            self.get_users()  # Call get_users to verify the stored data
            return rx.redirect('/try_login')


    def get_users(self):
        with Session(engine) as session:
            self.users = session.query(User).all()
            for user in self.users:
                print(f"User: {user.full_name}, Email: {user.email}, Mobile: {user.mobile_number},Password: {user.password}")



    def validate_password_set(self):
        password_pattern = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'
        if not re.match(password_pattern, self.password_set):
            self.password_set_error_message = "Password must be at least 8 characters long and contain both letters and numbers."
            return False
        else:
            self.password_set_error_message = ""
            return True

    
    def check_passwords(self):
        if self.validate_password_set():
            if self.password_set!= self.confirm_password_set:
                self.error_message_set = "Passwords do not match"
                return False
            else:
                self.error_message_set = ""  # Clear the error message if they match
                return True




    def update_password(self):
        salt = self.generate_salt()
        hashed_password = self.hash_password(self.password_set, salt)
        with Session(engine) as session:
            statement = select(User).where(User.email == self.email_forget)
            user = session.exec(statement).first()
            if user:
                user.password = hashed_password
                user.salt = salt
                session.add(user)
                session.commit()
                session.refresh(user)
                self.error_message_set = "Password updated successfully!"
            else:
                self.error_message_set = "User not found!"


    def handle_setpass_submit(self):
        if self.check_passwords():
            if not self.error_message_set:
                self.update_password()
                return rx.redirect('/loginpage')
            
        
    

    def handle_login_submit(self):
        if not self.email_log or not self.password_log:
            self.error_message_log = "Please enter all the details"
            return

        with Session(engine) as session:
            statement = select(User).where(User.email == self.email_log)
            user = session.exec(statement).first()
            if user and self.hash_password(self.password_log, user.salt) == user.password:
                self.error_message_log = "Login successful!"
                self.logged_in_email = self.email_log  # Store the logged-in user's email
                return rx.redirect('/logged_in_page')
            else:
                self.error_message_log = "Invalid email or password"

    def handle_email_verification(self):
        with Session(engine) as session:
            statement = select(User).where(User.email == self.email_forget)
            result = session.exec(statement).first()
            if result:
                self.email_verified = True
                self.reset_error_message = ""
                return rx.redirect('/setpassword')
            else:
                self.email_verified = False
                self.reset_error_message = "Email not found"

        