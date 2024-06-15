import reflex as rx

from .state import State




def handle_login_click():
    return rx.redirect('/loginpage')


def sign_up():
  return rx.card(
     
      
      rx.hstack(
         
        rx.divider(height='85px', width='400px', style={"background-color": "white"}),

        #main login box starts from here

          rx.vstack(
              rx.center(
                  rx.image(
                      src="/logos.webp",
                      width="10em",
                      height="auto",
                      border_radius="25%",
                  ),
                  rx.heading(
                      "Sign up to create your account",
                      size="6",
                      as_="h2",
                      text_align="center",
                      width="100%",
                  ),
                  direction="column",
                  spacing="5",
                  width="100%",
              ),
              rx.vstack(

                rx.cond(
                State.error_message,
                rx.text(State.error_message,
                    color="red",
                    size="4",
                    weight="medium",
                    text_align="left",
                    width="100%",
                    ),
                ),


                 rx.text(
                      "Full Name",
                      size="3",
                      weight="medium",
                      text_align="left",
                      width="100%",
                  ),
                  rx.input(
                      placeholder="Name",
                      type="name",
                      size="3",
                      width="100%",
                      on_change=State.set_full_name,
                  ),

                  rx.text(
                      "Mobile Number",
                      size="3",
                      weight="medium",
                      text_align="left",
                      width="100%",
                  ),
                  rx.input(
                      placeholder="9**********",
                      type="number",
                      size="3",
                      width="100%",
                      on_change=State.set_mobile_number,
                  ),
                  rx.cond(
                        State.mobile_error_message,
                        rx.text(State.mobile_error_message,
                            color="red",
                            size="3",
                            weight="medium",
                            text_align="left",
                            width="100%",
                        ),
                    ),

                  rx.text(
                      "Email address",
                      size="3",
                      weight="medium",
                      text_align="left",
                      width="100%",
                  ),
                  rx.input(
                      placeholder="user@reflex.dev",
                      type="email",
                      size="3",
                      width="100%",
                      on_change=State.set_email,
                  ),
                  rx.cond(
                        State.email_error_message,
                        rx.text(State.email_error_message,
                            color="red",
                            size="3",
                            weight="medium",
                            text_align="left",
                            width="100%",
                        ),
                    ),

                  justify="start",
                  spacing="2",
                  width="100%",
              ),
              rx.vstack(
                  rx.hstack(
                      rx.text(
                          "Choose your Password",
                          size="3",
                          weight="medium",
                      ),
                      rx.link(
                          "Forgot password?",
                          href="/forgetpass",
                          size="3",
                      ),
                      justify="between",
                      width="100%",
                  ),
                  rx.input(
                      placeholder="Choose your password",
                      type="password",
                      size="3",
                      width="100%",
                      on_change=State.set_password,
                  ),

                  rx.cond(
                        State.password_error_message,
                        rx.text(State.password_error_message,
                            color="red",
                            size="3",
                            weight="medium",
                            text_align="left",
                            width="100%",
                        ),
                    ),

                  spacing="2",
                  width="100%",
              ),
              rx.button(
                 "Sign up",
                 size="3",
                 width="100%",
                 on_click=State.handle_signup_submit,
                 ),
                

              rx.center(
                  rx.text("Have an Account?", size="3"),
                  rx.link("Login", size="3", on_click=handle_login_click),
                  opacity="0.8",
                  spacing="2",
                  direction="row",
              ),
              spacing="6",
              width="100%",
          ),

        rx.divider(height='85px', width='400px', style={"background-color": "white"}),

      ),

        
      size="4",
      justify_content = 'space-between',
      #max_width="28em",  # Consider removing redundant width="100%" here
  )


