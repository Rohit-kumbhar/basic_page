import reflex as rx
from .state import State




def navbar_link(text: str, url: str) -> rx.Component:
    return rx.link(
        rx.text(text, size="4", weight="medium"), href=url
    )

def handle_login_click():
    return rx.redirect('/loginpage')

def handle_signup_click():
    return rx.redirect('/sign_up_page')





def navbar():
    
    return rx.flex(
        rx.box(
            rx.image(src='/logos.webp', width='60px'),
        ),
        rx.hstack(
            navbar_link("Home", "http://localhost:3000/"),
            navbar_link("About", "/#"),
            navbar_link("Pricing", "/#"),
            navbar_link("Contact", "/#"),
            rx.button(
                "Sign Up",
                size="3",
                variant="outline",
                on_click=handle_signup_click,
            ),
            rx.button("Log In", size="3", on_click=handle_login_click),
            spacing="4",
            justify="end",
            align="center",
        ),
        justify_content="space-between",
        align="center",
        width="100%",  # Ensure the top-level flex covers the full width of the page
        padding="1em"
    )

def home():
    return rx.box(
        navbar(),
        rx.box(
            rx.text("Main content goes here"),
            padding="2em",
            width="100%",
        ),
        width="100%",  # Ensure the main content box covers the full width
    )

