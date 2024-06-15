"""Welcome to Reflex! This file outlines the steps to create a basic app."""

import reflex as rx

from .navbar import navbar
from .login_navbar import login_navbar
from .loginbox import logina
from .loginbox_navbar import home
from .forget_pass import forgetbox
from .setpass_box import setbox
from .footer import footer
from .signup_box import sign_up
from .logged_in import logged_in_box
from .logged_in_navbar import logged_navbar
from .try_login import post_signin


from .state import State

from rxconfig import config







def index():
    return rx.container(
       
        navbar(),
        rx.divider(height='35px', style={"background-color": "white"}),
        home(),
        footer(),
    )

def login():
    return rx.container(
        navbar(),
        rx.divider(height='35px', style={"background-color": "white"}),
        logina(),
        footer(),

    )


def sign_up_page():
    return rx.container(
        navbar(),
        rx.divider(height='35px', style={"background-color": "white"}),
        sign_up(),
        footer(),

    )

def forget_pass():
    return rx.container(
        navbar(),
        rx.divider(height='35px', style={"background-color": "white"}),
        forgetbox(),
        footer(),

    )


def set_pass():
    return rx.container(
        navbar(),
        rx.divider(height='35px', style={"background-color": "white"}),
        setbox(),
        footer(),

    )

def logged_in():
    return rx.container(
        navbar(),
        rx.divider(height='35px', style={"background-color": "white"}),
        logged_in_box(),
        footer(),

    )


def try_to_login():
    return rx.container(
        navbar(),
        rx.divider(height='35px', style={"background-color": "white"}),
        post_signin(),
        footer(),

    )




app = rx.App()
app.add_page(index)
app.add_page(login,route='/loginpage')
app.add_page(forget_pass,route='/forgetpass')
app.add_page(set_pass,route='/setpassword')
app.add_page(sign_up_page,route='/sign_up_page')
app.add_page(logged_in,route='/logged_in_page')
app.add_page(try_to_login,route='/try_login')

app._compile()
