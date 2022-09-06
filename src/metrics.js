const { MeterProvider } = require('@opentelemetry/sdk-metrics')
const { PrometheusExporter } = require('@opentelemetry/exporter-prometheus')

module.exports = function(port) {
	const meterProvider = new MeterProvider();
	const exporter = new PrometheusExporter({ port , preventServerStart: true })
	meterProvider.addMetricReader(exporter)
	const meter = meterProvider.getMeter('dov-bear')

	return { meter, exporter }
}

