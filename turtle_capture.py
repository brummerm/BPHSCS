"""
turtle_capture.py
A mock turtle module for the Classroom IDE sandbox.
Intercepts all turtle drawing commands, records them as a list of JSON
primitives, and writes canvas data to stdout after execution so the
browser can render it in an HTML5 canvas popup.

Injected by sandbox_runner.py as sys.modules['turtle'] before student
code is executed.
"""

import math
import json
import sys as _sys

# ── Global state ──────────────────────────────────────────────────────────────

_commands = []

_state = {
    'x':          0.0,
    'y':          0.0,
    'heading':    0.0,   # degrees; 0 = east, 90 = north (standard turtle)
    'pen_down':   True,
    'pen_color':  'black',
    'fill_color': 'black',
    'pen_size':   1,
    'visible':    True,
    'speed':      6,
    'filling':    False,
    'fill_pts':   [],
}

_canvas_width  = 500
_canvas_height = 500
_bg_color      = '#ffffff'   # turtle default is white
_did_output    = False


# ── Internal helpers ──────────────────────────────────────────────────────────

def _reset_state():
    global _commands, _bg_color, _did_output
    _commands  = []
    _bg_color  = '#ffffff'
    _did_output = False
    _state.update({
        'x': 0.0, 'y': 0.0, 'heading': 0.0,
        'pen_down': True, 'pen_color': 'black',
        'fill_color': 'black', 'pen_size': 1,
        'visible': True, 'speed': 6,
        'filling': False, 'fill_pts': [],
    })


def _record(cmd):
    _commands.append(cmd)


def _move(x2, y2):
    x1, y1 = _state['x'], _state['y']
    if _state['pen_down']:
        _record({
            'type':  'line',
            'x1': x1, 'y1': y1,
            'x2': x2, 'y2': y2,
            'color': _state['pen_color'],
            'width': _state['pen_size'],
        })
    if _state['filling']:
        _state['fill_pts'].append([x2, y2])
    _state['x'] = x2
    _state['y'] = y2


def _parse_color(*args):
    """Normalise turtle colour arguments to a CSS colour string."""
    if len(args) == 1:
        c = args[0]
        if isinstance(c, str):
            return c
        if isinstance(c, (tuple, list)) and len(c) == 3:
            r, g, b = c
            if all(isinstance(v, float) and 0.0 <= v <= 1.0 for v in (r, g, b)):
                return '#{:02x}{:02x}{:02x}'.format(
                    int(r * 255), int(g * 255), int(b * 255))
            return '#{:02x}{:02x}{:02x}'.format(int(r), int(g), int(b))
    elif len(args) == 3:
        r, g, b = args
        if all(isinstance(v, float) and 0.0 <= v <= 1.0 for v in (r, g, b)):
            return '#{:02x}{:02x}{:02x}'.format(
                int(r * 255), int(g * 255), int(b * 255))
        return '#{:02x}{:02x}{:02x}'.format(int(r), int(g), int(b))
    return 'black'


# ── Movement ──────────────────────────────────────────────────────────────────

def forward(distance):
    angle = math.radians(_state['heading'])
    _move(_state['x'] + distance * math.cos(angle),
          _state['y'] + distance * math.sin(angle))

fd = forward


def backward(distance):
    forward(-distance)

bk   = backward
back = backward


def right(angle):
    _state['heading'] -= angle

rt = right


def left(angle):
    _state['heading'] += angle

lt = left


def goto(x, y=None):
    if y is None:
        try:
            x, y = x
        except TypeError:
            y = 0.0
    _move(float(x), float(y))

setpos      = goto
setposition = goto


def setx(x):
    _move(float(x), _state['y'])


def sety(y):
    _move(_state['x'], float(y))


def home():
    _move(0.0, 0.0)
    _state['heading'] = 0.0


def setheading(angle):
    _state['heading'] = float(angle)

seth = setheading


# ── Pen control ───────────────────────────────────────────────────────────────

def penup():
    _state['pen_down'] = False

pu = penup
up = penup


def pendown():
    _state['pen_down'] = True

pd   = pendown
down = pendown


def pensize(width=None):
    if width is not None:
        _state['pen_size'] = max(1, int(width))
    return _state['pen_size']

width = pensize


def pencolor(*args):
    if args:
        _state['pen_color'] = _parse_color(*args)
    return _state['pen_color']


def fillcolor(*args):
    if args:
        _state['fill_color'] = _parse_color(*args)
    return _state['fill_color']


def color(*args):
    if not args:
        return (_state['pen_color'], _state['fill_color'])
    if len(args) == 1:
        c = _parse_color(args[0])
        _state['pen_color']  = c
        _state['fill_color'] = c
    elif len(args) == 2:
        _state['pen_color']  = _parse_color(args[0])
        _state['fill_color'] = _parse_color(args[1])


def speed(s=None):
    if s is not None:
        _state['speed'] = s
    return _state['speed']


def pendown():
    _state['pen_down'] = True

# ── Shapes ────────────────────────────────────────────────────────────────────

def begin_fill():
    _state['filling']   = True
    _state['fill_pts']  = [[_state['x'], _state['y']]]


def end_fill():
    if _state['filling'] and len(_state['fill_pts']) >= 3:
        _record({
            'type':   'fill',
            'points': _state['fill_pts'][:],
            'color':  _state['fill_color'],
        })
    _state['filling']  = False
    _state['fill_pts'] = []


def circle(radius, extent=None, steps=None):
    if extent is None:
        extent = 360
    n = steps if steps else max(8, int(abs(radius) * math.pi * abs(extent) / 180 / 3))
    step_angle  = extent / n
    step_length = 2 * abs(radius) * math.sin(math.radians(abs(step_angle) / 2))
    for _ in range(n):
        forward(step_length)
        left(step_angle)


def dot(size=None, *color_args):
    c  = _parse_color(*color_args) if color_args else _state['pen_color']
    sz = float(size) if size else max(2 * _state['pen_size'], 4)
    _record({
        'type':   'dot',
        'x': _state['x'], 'y': _state['y'],
        'radius': sz / 2,
        'color':  c,
    })


# ── Text ──────────────────────────────────────────────────────────────────────

def write(arg, move=False, align='left', font=('Arial', 8, 'normal')):
    _record({
        'type':  'text',
        'x': _state['x'], 'y': _state['y'],
        'text':  str(arg),
        'color': _state['pen_color'],
        'font':  list(font),
        'align': align,
    })


# ── State queries ─────────────────────────────────────────────────────────────

def pos():
    return (_state['x'], _state['y'])

position = pos


def xcor():
    return _state['x']


def ycor():
    return _state['y']


def heading():
    return _state['heading']


def isdown():
    return _state['pen_down']


def isvisible():
    return _state['visible']


def distance(x, y=None):
    if y is None:
        try:
            x, y = x
        except TypeError:
            y = 0.0
    return math.hypot(_state['x'] - x, _state['y'] - y)


def towards(x, y=None):
    if y is None:
        try:
            x, y = x
        except TypeError:
            y = 0.0
    return math.degrees(math.atan2(y - _state['y'], x - _state['x']))


# ── Visibility ────────────────────────────────────────────────────────────────

def hideturtle():
    _state['visible'] = False

ht = hideturtle


def showturtle():
    _state['visible'] = True

st = showturtle


# ── Screen / window ───────────────────────────────────────────────────────────

def bgcolor(*args):
    global _bg_color
    if args:
        _bg_color = _parse_color(*args)
    return _bg_color


def bgpic(picname=None):
    pass  # no-op


def setup(width=None, height=None, startx=None, starty=None):
    global _canvas_width, _canvas_height
    if width  and isinstance(width,  int): _canvas_width  = width
    if height and isinstance(height, int): _canvas_height = height


def screensize(canvwidth=None, canvheight=None, bg=None):
    global _canvas_width, _canvas_height
    if canvwidth:  _canvas_width  = canvwidth
    if canvheight: _canvas_height = canvheight


def title(string=''):
    pass  # no-op


def tracer(n=None, delay=None):
    pass  # no-op; no animation in sandbox


def update():
    pass  # no-op


def listen():
    pass


def onkey(fun, key):
    pass


def onkeypress(fun, key=None):
    pass


def onkeyrelease(fun, key=None):
    pass


def onclick(fun, btn=1, add=None):
    pass


def onscreenclick(fun, btn=1, add=None):
    pass


def ontimer(fun, t=0):
    pass


# ── Canvas output ─────────────────────────────────────────────────────────────

def _output_canvas():
    """Called by sandbox_runner after exec() to emit canvas data."""
    global _did_output
    if _did_output or not _commands:
        return
    _did_output = True
    payload = json.dumps({
        'commands': _commands,
        'width':    _canvas_width,
        'height':   _canvas_height,
        'bgcolor':  _bg_color,
    }, separators=(',', ':'))
    # Write to the real underlying stdout so it goes through the SSE stream.
    # sandbox_runner stores the original sys.stdout as _tc._REAL_OUT before
    # wrapping it in a LimitedStream.
    out = _REAL_OUT if _REAL_OUT is not None else _sys.__stdout__
    out.write('\n__TURTLE_CANVAS__:' + payload + '\n')
    out.flush()


_REAL_OUT = None   # Set by sandbox_runner.py before exec()


# ── reset / clear ─────────────────────────────────────────────────────────────

def clear():
    global _commands
    _commands = []


def reset():
    _reset_state()


def clearscreen():
    _reset_state()


# ── Loop / exit helpers ───────────────────────────────────────────────────────

def done():
    _output_canvas()


mainloop    = done
exitonclick = done


def bye():
    _output_canvas()


# ── Turtle class (OO API) ─────────────────────────────────────────────────────

class Turtle:
    """Minimal OO interface — delegates to the module-level functions."""

    def __init__(self, shape='classic', undobuffersize=None, visible=True):
        pass

    # movement
    def forward(self, d):    forward(d)
    def fd(self, d):         forward(d)
    def backward(self, d):   backward(d)
    def bk(self, d):         backward(d)
    def back(self, d):       backward(d)
    def right(self, a):      right(a)
    def rt(self, a):         right(a)
    def left(self, a):       left(a)
    def lt(self, a):         left(a)
    def goto(self, x, y=None): goto(x, y)
    def setpos(self, x, y=None): goto(x, y)
    def setposition(self, x, y=None): goto(x, y)
    def setx(self, x):       setx(x)
    def sety(self, y):       sety(y)
    def home(self):          home()
    def setheading(self, a): setheading(a)
    def seth(self, a):       setheading(a)

    # pen
    def penup(self):         penup()
    def pu(self):            penup()
    def up(self):            penup()
    def pendown(self):       pendown()
    def pd(self):            pendown()
    def down(self):          pendown()
    def pensize(self, w=None): return pensize(w)
    def width(self, w=None):   return pensize(w)
    def pencolor(self, *a):  return pencolor(*a)
    def fillcolor(self, *a): return fillcolor(*a)
    def color(self, *a):     return color(*a)
    def speed(self, s=None): return speed(s)

    # shapes
    def begin_fill(self):    begin_fill()
    def end_fill(self):      end_fill()
    def circle(self, r, e=None, s=None): circle(r, e, s)
    def dot(self, s=None, *c): dot(s, *c)
    def write(self, *a, **kw): write(*a, **kw)

    # visibility
    def hideturtle(self): hideturtle()
    def ht(self):         hideturtle()
    def showturtle(self): showturtle()
    def st(self):         showturtle()
    def isvisible(self):  return isvisible()
    def isdown(self):     return isdown()

    # queries
    def pos(self):              return pos()
    def position(self):         return pos()
    def xcor(self):             return xcor()
    def ycor(self):             return ycor()
    def heading(self):          return heading()
    def distance(self, x, y=None): return distance(x, y)
    def towards(self, x, y=None):  return towards(x, y)

    # clear
    def clear(self):  clear()
    def reset(self):  reset()

    # screen
    def getscreen(self): return Screen()
    def screen(self):    return Screen()

    # no-ops
    def shape(self, name=None): pass
    def stamp(self): return 0
    def clearstamp(self, stampid): pass
    def shapesize(self, *a, **kw): pass
    def resizemode(self, *a): pass
    def turtlesize(self, *a, **kw): pass
    def undo(self): pass
    def onclick(self, *a, **kw): pass
    def onrelease(self, *a, **kw): pass
    def ondrag(self, *a, **kw): pass

    # make it work with "t = Turtle()" then calling methods
    def __repr__(self):
        return f'<Turtle at ({_state["x"]:.1f}, {_state["y"]:.1f})>'


RawTurtle  = Turtle
RawPen     = Turtle


# ── Screen class ──────────────────────────────────────────────────────────────

class Screen:
    """Minimal Screen object returned by turtle.Screen() / getscreen()."""

    def bgcolor(self, *args): return bgcolor(*args)
    def bgpic(self, *args): pass
    def setup(self, *args, **kwargs): setup(*args, **kwargs)
    def screensize(self, *a, **kw): pass
    def title(self, s): pass
    def tracer(self, *a, **kw): pass
    def update(self): pass
    def listen(self): pass
    def onkey(self, *a, **kw): pass
    def onkeypress(self, *a, **kw): pass
    def onkeyrelease(self, *a, **kw): pass
    def onclick(self, *a, **kw): pass
    def onscreenclick(self, *a, **kw): pass
    def ontimer(self, *a, **kw): pass
    def exitonclick(self): _output_canvas()
    def mainloop(self): _output_canvas()
    def bye(self): _output_canvas()
    def turtles(self): return []
    def window_width(self): return _canvas_width
    def window_height(self): return _canvas_height
    def getcanvas(self): return None

    def addshape(self, *a, **kw): pass
    def register_shape(self, *a, **kw): pass
    def colormode(self, cmode=None): return 255

    def __repr__(self):
        return '<TurtleScreen (mock)>'


TurtleScreen = Screen


def getscreen():
    return Screen()


def turtles():
    return []


def window_width():
    return _canvas_width


def window_height():
    return _canvas_height


def colormode(cmode=None):
    return 255