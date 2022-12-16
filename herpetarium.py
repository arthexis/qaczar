import turtle
import random

# Set up the screen
turtle.setup(800, 600)
wn = turtle.Screen()
wn.bgcolor("lightgreen")
wn.title("Herpetarium")

# Create a turtle
tess = turtle.Turtle()
tess.color("blue")
tess.pensize(3)

# Create a list of colors
colors = ["red", "green", "blue", "orange", "purple", "yellow"]

# Create a list of shapes
shapes = ["arrow", "turtle", "circle", "square", "triangle", "classic"]

# Create a list of pensizes
pensizes = [1, 2, 3, 4, 5, 6]

# Create a list of speeds
speeds = [1, 2, 3, 4, 5, 6]

# Create a list of positions
positions = [(0, 0), (-100, 0), (100, 0), (0, 100), (0, -100)]

# Create a list of headings
headings = [0, 90, 180, 270]

# Start the game
for i in range(10):
    # Randomly choose a color, shape, pensize, speed, position, and heading
    color = random.choice(colors)
    shape = random.choice(shapes)
    pensize = random.choice(pensizes)
    speed = random.choice(speeds)
    position = random.choice(positions)
    heading = random.choice(headings)

    # Create a new turtle
    new_turtle = turtle.Turtle()
    new_turtle.color(color)
    new_turtle.shape(shape)
    new_turtle.pensize(pensize)
    new_turtle.speed(speed)
    new_turtle.penup()
    new_turtle.setpos(position)
    new_turtle.setheading(heading)
    new_turtle.pendown()

    # Draw a square
    for i in range(4):
        new_turtle.forward(50)
        new_turtle.left(90)

# Exit on click
wn.exitonclick()


