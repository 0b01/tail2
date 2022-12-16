import { h } from 'preact';
import React from 'preact/compat';
import LineChart from '../../charts/LineChart01';
import Icon from '../../images/icon-01.svg';
import EditMenu from '../EditMenu';

// Import utilities
import { tailwindConfig, hexToRGB } from '../../utils/Utils';
import { HeatMapGrid } from '../../heatmap';

function DashboardCard01() {
  const xLabels = new Array(24).fill(0).map((_, i) => `${i}`)
  const yLabels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri']
  const data = new Array(yLabels.length)
    .fill(0)
    .map(() =>
      new Array(xLabels.length).fill(0).map(() => Math.floor(Math.random() * 50 + 50))
    )


  return (
    <div className="flex flex-col col-span-full sm:col-span-6 xl:col-span-4 bg-white shadow-lg rounded-sm border border-slate-200">
      <div className="px-5 pt-5">
        <h2 className="text-lg font-semibold text-slate-800 mb-2">Heatmap</h2>
        {/* <div className="text-xs font-semibold text-slate-400 uppercase mb-1">Sales</div>
        <div className="flex items-start">
          <div className="text-3xl font-bold text-slate-800 mr-2">$24,780</div>
          <div className="text-sm font-semibold text-white px-1.5 bg-green-500 rounded-full">+49%</div>
        </div> */}
      </div>
      <div className="grow m-6">
        {/* <LineChart data={chartData} width={389} height={128} /> */}
        <HeatMapGrid
          data={data}
          xLabels={xLabels}
          yLabels={yLabels}
          // Reder cell with tooltip
          cellRender={(x, y, value) => (
            // <div>{value}</div>
            <div></div>
          )}
          xLabelsStyle={index => ({
            color: index % 2 ? "transparent" : "#777",
            fontSize: ".65rem"
          })}
          yLabelsStyle={() => ({
            fontSize: ".65rem",
            textTransform: "uppercase",
            color: "#777"
          })}
          cellStyle={(_x, _y, ratio) => ({
            background: `rgb(12, 100, 100, ${ratio})`,
            fontSize: ".7rem",
            color: `rgb(0, 0, 0, ${ratio / 2 + 0.4})`
          })}
          cellHeight="1.5rem"
          xLabelsPos="bottom"
          onClick={(x, y) => alert(`Clicked (${x}, ${y})`)}
          // yLabelsPos="right"
          square
        />



      </div>
    </div>
  );
}

export default DashboardCard01;
