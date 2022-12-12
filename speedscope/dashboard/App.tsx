import {h, render} from 'preact'
import Dashboard from './Dashboard';

declare const module: any
if (module.hot) {
  module.hot.dispose(() => {
    // Force the old component go through teardown steps
    render(<div />, document.body, document.body.lastElementChild || undefined)
  })
  module.hot.accept()
}

render(
  <div>
    <Dashboard />
  </div>,
  document.body,
  document.body.lastElementChild || undefined,
)
