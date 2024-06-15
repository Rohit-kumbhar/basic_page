import reflex as rx


def navbar_link(text: str, url: str) -> rx.Component:
    return rx.link(
        rx.text(text, size="4", weight="medium"), href=url
    )

def login_navbar():
    return rx.flex(

        rx.box(
            rx.image(src='/logos.webp',
            width='60px')
        ),
    
        rx.box(
            rx.hstack(
                navbar_link("Home", "http://localhost:3000/"),
                navbar_link("About", "/#"),
                navbar_link("Pricing", "/#"),
                navbar_link("Contact", "/#"),
                #spacing="5",
                
                rx.button(
                    "Sign Up",
                    size="3",
                    variant="outline",
                    
                        ),
                    rx.button("Log In", size="3"),
                        spacing="4",
                        justify="end",
                ),

           ),

        
        justify_content = 'space-between',

    
    )         
            