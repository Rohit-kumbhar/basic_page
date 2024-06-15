import reflex as rx

from .state import State


def setbox():
    return rx.card(
        rx.hstack(
            rx.divider(height="85px", width="400px", style={"background-color": "white"}),

            # Main login box starts from here
            rx.vstack(
                rx.center(
                    rx.image(
                        src="/logos.webp",
                        width="10em",
                        height="auto",
                        border_radius="25%",
                    ),
                    direction="column",
                    spacing="5",
                    width="100%",
                ),
                rx.vstack(

                    rx.text(
                    State.error_message_set,
                    color="red",
                    size="4",
                    weight="medium",
                    text_align="left",
                    width="100%",
                ),
                    rx.text(
                        "Enter New Password",
                        size="3",
                        weight="medium",
                        text_align="left",
                        width="100%",
                    ),
                    rx.input(
                        type="password",
                        size="3",
                        width="100%",
                        on_change=State.set_password_set  # Update password state
                    ),
                    rx.text(
                    State.password_set_error_message,
                    color="red",
                    size="4",
                    weight="medium",
                    text_align="left",
                    width="100%",
                    ),
                    rx.text(
                        "Confirm your Password",
                        size="3",
                        weight="medium",
                        text_align="left",
                        width="100%",
                    ),
                    rx.input(
                        type="password",
                        size="3",
                        width="100%",
                        on_change=State.set_confirm_password_set  # Update confirm password state
                    ),
                    justify="start",
                    spacing="2",
                    width="100%",
                ),
                
                rx.button(
                    "Submit",
                    size="3",
                    width="100%",
                    on_click=State.handle_setpass_submit
                    ),
                    
                    spacing="6",
                    width="100%",
            ),
            rx.divider(height="85px", width="400px", style={"background-color": "white"}),
        ),
        size="4",
        justify_content="space-between",
    )

