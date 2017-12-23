from z3 import *
import time

def feed_model_performance():
    a = Int('a')
    b = Int('b')
    z = Int('z')
    solver = Solver()
    solver.add(a<6)
    solver.add(b>3)
    solver.add(z==(4*a+6*b))
    solver.add((a+b)<7)
    solver.add(z<16)
    cur_time = time.time()
    model = solver.check()
    print "Duration %s %s" % (time.time()-cur_time,model)

def feed_model_performance_2():
    a = Int('a')
    b = Int('b')
    z = Int('z')
    z1 = Int('z1')
    solver = Solver()
    solver.add(a < 6)
    solver.add(b > 3)
    solver.add(z==(4 * a + 6 * b))
    solver.add(z1!=And(a==-2,b==4))
    solver.add((a + b) < 7)
    solver.add(z1 < 14)
    cur_time = time.time()
    model = solver.check()
    print "Duration %s %s" % (time.time() - cur_time,model)

def feed_model_performance_3():
    a = Int('a')
    b = Int('b')
    z = Int('z')
    z1 = Int('z1')
    solver = Solver()
    solver.add(a < 6)
    solver.add(b > 3)
    solver.add(z==(4 * a + 6 * b))
    solver.add(z1==If(And(a==-2,b==4),16,z))
    solver.add((a + b) < 7)
    solver.add(z1 < 14)
    cur_time = time.time()
    model = solver.check()
    print "Duration %s %s" % (time.time() - cur_time,model)


# feed_model_performance()
feed_model_performance_2()
feed_model_performance_3()