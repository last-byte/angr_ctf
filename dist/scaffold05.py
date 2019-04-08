import angr
import claripy
import sys

def main(argv):
  path_to_binary = "05_angr_symbolic_memory"
  project = angr.Project(path_to_binary)

  start_address = 0x8048601
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s %8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 64)
  password1 = claripy.BVS('password0', 64)
  password2 = claripy.BVS('password0', 64)
  password3 = claripy.BVS('password0', 64)

  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)
  password0_address = 0xa1ba1c0
  initial_state.memory.store(password0_address, password0)
  initial_state.memory.store(password0_address + 0x8,  password1)
  initial_state.memory.store(password0_address + 0x10, password2)
  initial_state.memory.store(password0_address + 0x18, password3)
  

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.\n' in stdout_output:
      return True
    else: return False

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.\n' in stdout_output:
      return True
    else: return False

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=str
    # which returns a string instead of an integer.
    # (!)
    solution0 = solution_state.solver.eval(password0,cast_to=bytes)
    solution1 = solution_state.solver.eval(password1,cast_to=bytes)
    solution2 = solution_state.solver.eval(password2,cast_to=bytes)
    solution3 = solution_state.solver.eval(password3,cast_to=bytes)
    
    solution = solution0 + solution1 + solution2 + solution3

    print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
