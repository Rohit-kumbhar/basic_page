import reflex as rx

def container_with_image_and_text(img_src, text):
    return rx.chakra.container(
        rx.vstack(
            rx.image(src=img_src),
            rx.text(text),
            spacing="2",
            align="center"

        ),
        center_content=True,
        bg="white",  # Change background color to white
        width="100%",
        padding="1em",
        border_radius="15px",  # Add curved edges
        border_color="lightgrey",  # Add light grey border color
        border_width="1px",  # Set border width
        box_shadow="0 4px 8px rgba(0, 0, 0, 0.1)",  # Add shadow
    )


def icon_with_text(tag, text):
    return rx.vstack(
        rx.icon(tag=tag, size=24),  # Adjust size as needed
        rx.text(text, size="4"),
        align="center",
        spacing="5",
        justify_content="space-between",
        margin_left="150px",
        margin_right="150px",
    )




def row_with_icon_heading_text(icon_tag, heading_text, sentence):
    return rx.box(
        rx.hstack(
            rx.icon(tag=icon_tag, size=24),  # Adjust the icon size as needed
            rx.box(
                rx.heading(heading_text, size="4", weight="medium"),  # Adjust the heading size and weight as needed
                rx.text(sentence, size="3"),  # Adjust the text size as needed
                align="start"
            ),
            spacing="4",
            align="center"
        ),
        border_bottom="1px solid lightgrey",  # Add a light grey border between rows
        padding="1em",  # Add padding for better spacing
    )

def handle_signup_click():
    return rx.redirect('/sign_up_page')




def home():
    return rx.box(  # Use rx.box to allow full-width layout
        rx.card(
            rx.vstack(
                rx.hstack(
                    rx.box(
                        rx.heading(
                            "Turn Enterprise Data Into",
                            size="9",  # Adjust size as needed
                            weight="bold",  # Make the text bold
                            margin_bottom="22px"  # Add 100px space below this heading
                        ),
                        rx.heading(
                            "Insights with LlamaCloud",
                            size="9",  # Adjust size as needed
                            weight="bold"  # Make the text bold
                        ),
                        align_items="center",  # Center items along the cross axis
                        justify_content="center",  # Center items along the main axis
                        width="100%",
                        text_align="center",  # Center text inside the box
                        margin_top="12vh",  # Add space from the top
                    ),
                    width="100%",
                    justify_content="center",  # Center the box inside the hstack
                    size="4",
                ),
                rx.box(
                    rx.text(
                        "A turn-key solution to build an API backed by your data and enhanced by generative AI, hosted on our cloud or built into yours.",
                        size="4",  # Adjust size as needed
                        weight="bold",  # Make the text bold
                        color="gray"  # Change text color to grey
                    ),
                    align_items="center",  # Center items along the cross axis
                    justify_content="center",  # Center items along the main axis
                    text_align="center",  # Center text inside the box
                    margin_top="50px",  # Add space between the two boxes
                ),
                rx.hstack(
                    rx.button(
                        "SIGN UP",
                        color_scheme="green",
                        size="3",
                        on_click=handle_signup_click,
                    ),
                    rx.button(
                        "TALK TO US",
                        color_scheme="green",
                        size="3"
                    ),
                    spacing="4",  # Adjust spacing as needed
                    margin_top="25px",
                    justify="center",  # Center the card content
                    align="center",
                    width="100%",
                ),
                rx.hstack(
                    container_with_image_and_text("/img1.webp", "Proprietary parsing for complex documents with embedded objects such as tables and figures."),
                    container_with_image_and_text("/img2.webp", "Proprietary parsing for complex documents with embedded objects such as tables and figures."),
                    container_with_image_and_text("/img3.webp", "Proprietary parsing for complex documents with embedded objects such as tables and figures."),
                    spacing="2",  # Add spacing between containers
                    width="100%",
                    margin_top="75px",
                ),


                rx.hstack(
                    icon_with_text("home", "Home"),
                    icon_with_text("info", "Info"),
                    icon_with_text("contact", "Contact"),
                    spacing="4",
                    justify="center",
                    width="100%",
                    margin_top="75px",
                ),




               rx.hstack(
                 
                        rx.heading(
                            "Industry-leading document parsing with LlamaParse",
                            size="7",  # Adjust size as needed
                            weight="bold",  # Make the text bold
                            margin_bottom="22px", # Add 100px space below this heading
                            width="40%",
                            align_items="top",
                        ),
                        rx.vstack(
                          rx.heading(
                              "Your outcomes are only as good as your data",
                              size="7",  # Adjust size as needed
                              weight="bold"  # Make the text bold
                          ),
                          rx.text(
                            "Clearly and correctly parsing unstructured files like PDFs, PowerPoints, and Word documents can make a huge difference to how understandable they are to an LLM application, and therefore your results. LlamaParse is an industry-leading solution for parsing dozens of types of complex documents.",
                            size="4",  # Adjust size as needed
                            weight="bold",  # Make the text bold
                            color="gray"  # Change text color to grey
                                 ),
                          rx.heading(
                            "Heading",
                            size="6",  # Adjust size as needed
                            weight="bold",  # Make the text bold
                            margin_top="22px", # Add 100px space below this heading
                          ),
                           rx.hstack(
                              container_with_image_and_text("/img1.webp", "Proprietary parsing for complex documents with embedded objects such as tables and figures."),
                              container_with_image_and_text("/img2.webp", "Proprietary parsing for complex documents with embedded objects such as tables and figures."),
                              spacing="2",  # Add spacing between containers
                              #width="100%",
                              margin_top="25px",
                          ),

                          width="60%"
                        ),

                        #align_items="center",  # Center items along the cross axis
                        #justify_content="center",  # Center items along the main axis
                        #width="100%",
                        text_align="left",  # Center text inside the box
                        margin_top="12vh",  # Add space from the top
                        size="4",
    
                ),



                rx.hstack(
                 
                        rx.box(
                          rx.heading(
                              "Industry-leading document parsing with LlamaParse",
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
                    
                        width="45%",
                          
                        ),



                        rx.vstack(
                          rx.vstack(
                            row_with_icon_heading_text("home", "Home Heading", "This is a sentence about home.it talks about it"),
                            row_with_icon_heading_text("info", "Info Heading", "This is a sentence about info.it talks about it"),
                            row_with_icon_heading_text("contact", "Contact Heading", "This is a sentence about contact.it talks about it"),
                            row_with_icon_heading_text("settings", "Settings Heading", "This is a sentence about settings.it talks about it"),
                            spacing="4",
                            width="100%",
                            align="start",
                          ),

                          width="55%"
                        ),

                        #align_items="center",  # Center items along the cross axis
                        #justify_content="center",  # Center items along the main axis
                        #width="100%",
                        text_align="left",  # Center text inside the box
                        margin_top="12vh",  # Add space from the top
                        size="4",
    
                ),



            ),
            
        ),
        

    )

