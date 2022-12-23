import RightSvg from "../../components/header/svg/right-svg";

import { motion } from 'framer-motion';

const FaqSection = () => {

    const faqVariants = {
        initial: {
            x: -100,
            opacity: 0
        },
        animate: {
            x: 0,
            opacity: 1,
            transition: {
                duration: 0.66
            }
        }
    }

    return (
        <section className="py-5 relative">
            <div className="container mx-auto px-10 border-b border-gray-800 pb-10">
                <div className="grid">
                    <motion.div
                        className=""
                        variants={faqVariants}
                        initial="initial"
                        whileInView="animate"
                        viewport={{ once: true }}
                    >
<h2 id="what-is-tail2-continuous-profiler-">What is tail2?</h2>
<p>tail2 is a <em>self-service continuous profiler</em> that can be run in your production environment.</p>
<h2 id="what-is-continuous-profiling-">What is continuous profiling?</h2>
<p>Continuous profiling is <strong>always-on system-wide profiling</strong>, rather than being limited to a specific application or process.</p>
<p>A continuous profiler is constantly running in the background, collecting data on the performance of the entire system. This allows developers to get a comprehensive view of the performance of their systems and applications.</p>
<h2 id="why-continuous-profiling-">Why?</h2>
<p>Continuous profiling is particularly useful for identifying issues that may not be immediately apparent when profiling a single application or process. For example, it can help developers quickly identify performance bottlenecks that are caused by interactions between multiple applications or processes, or by external factors such as kernel resource contention or networking hardware limitations.</p>
<p>It&#39;s <strong>magical</strong> to see exactly what your application is doing.</p>
<h2 id="what-languages-runtimes-are-supported-">What languages/runtimes are supported?</h2>
<p>Currently we support native languages such as C/C++, Rust, Go and others.</p>
<p>Scripting languages support: Python3.11.</p>
<p>We don&#39;t currently support JIT runtimes but we are working on Java, .NET, Node.JS and wasmtime support.</p>
<h2 id="how-to-use-tail2-">How to use tail2?</h2>
<p>tail2 is designed to be easy to integrate, without <em>any</em> changes to your code.</p>
<p>It is not yet ready for production but you can join our discord and chat with the community!</p>
                    </motion.div>
                </div>
            </div>
            <div className="absolute top-0 right-0">
                <RightSvg />
            </div>
        </section>
    )
}

export default FaqSection;