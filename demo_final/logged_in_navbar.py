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





def logged_navbar():
    
    return rx.flex(
        rx.box(
            rx.image(src='/logos.webp', width='60px'),
        ),
        rx.hstack(
            navbar_link("Home", "/logged_in_page"),
            navbar_link("About", "/logged_in_page"),
            navbar_link("Pricing", "/logged_in_page"),
            navbar_link("Contact", "/logged_in_page"),


        #     rx.button(
        #         "Sign Up",
        #         size="3",
        #         variant="outline",
        #         on_click=handle_signup_click,
        #     ),
        #     rx.button("Log In", size="3", on_click=handle_login_click),
        #     spacing="4",
        #     justify="end",
        #     align="center",
        # 


        ),
        justify_content="space-between",
        align="center",
        width="100%",  # Ensure the top-level flex covers the full width of the page
        padding="1em"
    )


