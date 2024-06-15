import reflex as rx
from .state import State

def handle_login_click():
    return rx.redirect('/loginpage')



def post_signin():
    return rx.hstack(
    rx.flex(
 
                rx.hstack(
                 
                        rx.box(
                          rx.heading(
                              "Thanks For Signing In",
                              size="7",  # Adjust size as needed
                              weight="bold",  # Make the text bold
                              margin_bottom="22px", # Add 100px space below this heading
                              #width="40%",
                              align_items="top",
                          ),
                          rx.text(
                            "Candable they are to an LLM application, and therefore your results. LlamaParse is an industry-leading solution for parsing dozens of types of complex documents.",
                            size="4",  # Adjust size as needed
                            weight="bold",  # Make the text bold
                            color="gray"  # Change text color to grey
                                 ),


                          rx.button(
                            "Click here to LogIn",
                            color_scheme="green",
                            size="3",
                            #spacing="4",  # Adjust spacing as needed
                            margin_top="25px",
                            #justify="center",  # Center the card content
                            #align="center",
                            #width="100%",
                            on_click=handle_login_click,
                           ),
                    
                        width="100%",
                          
                        ),
                ),

    ),

    )

