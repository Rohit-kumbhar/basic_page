import reflex as rx

from .state import State

def navbar_link(text: str, url: str) -> rx.Component:
    return rx.link(
        rx.text(text, size="4", weight="medium"), href=url
    )


def handle_signup_click():
    return rx.redirect('/sign_up_page')



def logina():
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
                      "Sign in to your account",
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
                    State.error_message_log,
                    rx.text(State.error_message_log,
                        color="red",
                        size="4",
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
                      on_change=State.set_email_log,
                  ),
                  


                  justify="start",
                  spacing="2",
                  width="100%",
              ),
              rx.vstack(
                  rx.hstack(
                      rx.text(
                          "Password",
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
                      placeholder="Enter your password",
                      type="password",
                      size="3",
                      width="100%",
                      on_change=State.set_password_log,
                  ),
                  spacing="2",
                  width="100%",
              ),
              rx.button(
                 "Sign in",
                 size="3",
                 width="100%",
                 on_click=State.handle_login_submit,
                 ),
                
              rx.center(
                  rx.text("New here?", size="3"),
                  rx.link("Sign up", size="3",on_click=handle_signup_click),
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


