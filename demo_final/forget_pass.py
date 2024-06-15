import reflex as rx

from .state import State

def handle_login_click():
            return rx.redirect('/setpassword')

def forgetbox():
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
                  
                  direction="column",
                  spacing="5",
                  width="100%",
              ),
              rx.vstack(
                     
                  rx.cond(
                    State.reset_error_message,
                    rx.text(State.reset_error_message,
                        color="red",
                        size="4",
                        weight="medium",
                        text_align="left",
                        width="100%",
                        ),
                    ),

                  rx.text(
                      "Enter Your Email address",
                      size="3",
                      weight="medium",
                      text_align="left",
                      width="100%",
                  ),
                  rx.input(
                      type="email",
                      size="3",
                      width="100%",
                      on_change=State.set_email_forget,
                  ),
                  justify="start",
                  spacing="2",
                  width="100%",
              ),
              
              rx.button(
                "Submit",
                size="3",
                width="100%",
                # on_click=handle_login_click),
                on_click=State.handle_email_verification,
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


