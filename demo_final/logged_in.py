import reflex as rx
from .state import State



def handle_logout_click():
    return rx.redirect('http://localhost:3000/')



def sidebar_item(
    text: str, icon: str, href: str
) -> rx.Component:
    return rx.link(
        rx.hstack(
            rx.icon(icon),
            rx.text(text, size="4"),
            width="100%",
            padding_x="0.5rem",
            padding_y="0.75rem",
            align="center",
            style={
                "_hover": {
                    "bg": rx.color("accent", 4),
                    "color": rx.color("accent", 11),
                },
                "border-radius": "0.5em",
            },
        ),
        href=href,
        underline="none",
        weight="medium",
        width="100%",
    )


def sidebar_items() -> rx.Component:
    return rx.vstack(
        sidebar_item("Dashboard", "layout-dashboard", "/logged_in_page"),
        sidebar_item("Projects", "square-library", "/logged_in_page"),
        sidebar_item("Analytics", "bar-chart-4", "/logged_in_page"),
        sidebar_item("Messages", "mail", "/logged_in_page"),
        spacing="1",
        width="100%",
    )










def sidebar_bottom_profile() -> rx.Component:
    return rx.box(
        rx.desktop_only(
            rx.vstack(
                rx.hstack(
                    rx.image(
                        src="/logos.webp",
                        width="2.25em",
                        height="auto",
                        border_radius="25%",
                    ),
                    rx.heading(
                        "Demo", size="7", weight="bold"
                    ),
                    align="center",
                    justify="start",
                    padding_x="0.5rem",
                    width="100%",
                ),
                sidebar_items(),
                rx.spacer(),
                rx.vstack(
                    rx.vstack(
                        sidebar_item(
                            "Settings", "settings", "/logged_in_page"
                        ),
                        # sidebar_item(
                        #     "Log out", "log-out", "/#"
                        # ),


                        rx.button(
                            "Logout",
                            size="3",
                            width="100%",
                            # on_click=handle_login_click),
                            on_click=handle_logout_click,
                            ),

                        spacing="1",
                        width="100%",
                    ),
                    rx.divider(),
                    rx.hstack(
                        rx.icon_button(
                            rx.icon("user"),
                            size="3",
                            radius="full",
                        ),
                        rx.vstack(
                            rx.box(
                                rx.text(
                                    "My account",
                                    size="3",
                                    weight="bold",
                                ),
                                rx.text(
                                    "username",  # Display the logged-in user's email #not working need to debug
                                    size="2",
                                    weight="medium",
                                    color="green",
                                ),
                                width="100%",
                            ),
                            spacing="0",
                            align="start",
                            justify="start",
                            width="100%",
                        ),
                        padding_x="0.5rem",
                        align="center",
                        justify="start",
                        width="100%",
                    ),
                    width="100%",
                    spacing="5",
                ),
                spacing="5",
                # position="fixed",
                # left="0px",
                # top="0px",
                # z_index="5",
                padding_x="1em",
                padding_y="1.5em",
                bg=rx.color("accent", 3),
                align="start",
                # height="100%",
                height="650px",
                width="16em",
            ),
        ),
        rx.mobile_and_tablet(
            rx.drawer.root(
                rx.drawer.trigger(
                    rx.icon("align-justify", size=30)
                ),
                rx.drawer.overlay(z_index="5"),
                rx.drawer.portal(
                    rx.drawer.content(
                        rx.vstack(
                            rx.box(
                                rx.drawer.close(
                                    rx.icon("x", size=30)
                                ),
                                width="100%",
                            ),
                            sidebar_items(),
                            rx.spacer(),
                            rx.vstack(
                                rx.vstack(
                                    sidebar_item(
                                        "Settings",
                                        "settings",
                                        "/#",
                                    ),
                                    sidebar_item(
                                        "Log out",
                                        "log-out",
                                        "/#",
                                    ),
                                    width="100%",
                                    spacing="1",
                                ),
                                rx.divider(margin="0"),
                                rx.hstack(
                                    rx.icon_button(
                                        rx.icon("user"),
                                        size="3",
                                        radius="full",
                                    ),
                                    rx.vstack(
                                        rx.box(
                                            rx.text(
                                                "My account",
                                                size="3",
                                                weight="bold",
                                            ),
                                            rx.text(
                                                State.logged_in_email,  # Display the logged-in user's email
                                                size="2",
                                                weight="medium",
                                            ),
                                            width="100%",
                                        ),
                                        spacing="0",
                                        justify="start",
                                        width="100%",
                                    ),
                                    padding_x="0.5rem",
                                    align="center",
                                    justify="start",
                                    width="100%",
                                ),
                                width="100%",
                                spacing="5",
                            ),
                            spacing="5",
                            width="100%",
                        ),
                        top="auto",
                        right="auto",
                        height="100%",
                        width="20em",
                        padding="1.5em",
                        bg=rx.color("accent", 2),
                    ),
                    width="100%",
                ),
                direction="left",
            ),
            padding="1em",
        ),
    )





        


def logged_in_box():
    return rx.hstack(
    rx.flex(
 
                rx.hstack(
                 
                        rx.box(
                          rx.heading(
                              "Welcome to the new era of AI",
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
                            "TALK TO US",
                            color_scheme="green",
                            size="3",
                            #spacing="4",  # Adjust spacing as needed
                            margin_top="25px",
                            #justify="center",  # Center the card content
                            #align="center",
                            #width="100%",
                           ),
                    
                        width="90%",
                          
                        ),



                        rx.vstack(
                          rx.vstack(
                               

                                   rx.box(
                                        sidebar_bottom_profile(),
                                        #bg=rx.color("accent", 7),
                                        width="100%",
                                        height="100%",
                                        ),

                            
                          ),

                          width="10%"
                        ),

                        #align_items="center",  # Center items along the cross axis
                        #justify_content="center",  # Center items along the main axis
                        #width="100%",
                        text_align="left",  # Center text inside the box
                        margin_top="12vh",  # Add space from the top
                        size="4",
    
                ),



        
    ),

    )





    


        
    


