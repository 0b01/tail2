import type { NextComponentType } from 'next';

import Image from 'next/image';

import HeaderImg from '../../assets/images/header.png';

import LeftSvg from './svg/left-svg';
import RightSvg from './svg/right-svg';

import { motion } from 'framer-motion';

const Header: NextComponentType = () => {

    const imageContainerStyles = {
        height: 800,
        maxWidth: '768px',
        maxHeight: '800px',
        margin: 'auto'
    };

    const headerVariants = { 
        initial: {
            y: -100,
            opacity: 0
        },
        animate: {
            y: 0,
            opacity: 1,
            transition: {
                duration: 0.66
            }
        }
    };

    return (
        <motion.header
            className='py-24 relative'
            variants={headerVariants}
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
        >
            <div className="container mx-auto px-10 border-b border-gray-800">
                <div className='text-center'>
                    <div>
                        <h2 className='text-3xl md:text-4xl lg:text-6xl font-bold header-color w-3/4 mx-auto my-5'>
                            The Next-Generation Profiler</h2>
                        <p className='text-color my-5 w-2/4 mx-auto text-sm md:text-lg lg:text-lg'>
                            Profile all layers of your stack, all the time with so little overhead. No code change required.
                        </p>
                    </div>
                    <div style={imageContainerStyles}>
                        {/* <Image src={HeaderImg} /> */}
                        <iframe src="/flamegraph/app.html?profileURL=data/sample.txt" style={{height:"100%", width: "100%"}}></iframe>
                    </div>
                    <div>
                        <h2 className='text-lg md:text-2xl lg:text-4xl font-bold header-color w-2/4 mx-auto mt-10 mb-5'>
                            The Always-On Profiler
                        </h2>
                        <p className='text-color my-5 w-2/4 mx-auto text-sm md:text-lg lg:text-lg'>
                            Understand the runtime behavior of your app, optimize performance and resolve issues quickly and easily with tail2.
                        </p>
                    </div>
                </div>

                {/* <div className='grid md:grid-cols-1 lg:grid-cols-3 gap-5 p-5 box-bg text-center my-20'>
                    <div className='py-5 lg:border-r lg:border-gray-700'>
                        <h3 className='text-3xl lg:text-5xl font-bold main-color my-2'>0</h3>
                        <p className='text-color text-sm md:text-lg w-3/4 mx-auto'>No code change required. Simply deploy the agent and receive stacks.</p>
                    </div>
                    <div className='py-5 border-r border-gray-700'>
                        <h3 className='text-3xl lg:text-5xl font-bold main-color my-2'>1ms</h3>
                        <p className='text-color text-sm md:text-lg w-3/4 mx-auto'>Time to </p>
                    </div>
                    <div className='py-5'>
                        <h3 className='text-3xl lg:text-5xl font-bold main-color my-2'>&lt;1%</h3>
                        <p className='text-color text-sm md:text-lg w-3/4 mx-auto'>CPU used by tail2 when running in production</p>
                    </div>
                </div> */}

            </div>
            <div className='absolute top-0 right-0 -z-10'>
                <RightSvg />
            </div>
            <div className='absolute top-0 left-0 -z-10 md:block hidden'>
                <LeftSvg />
            </div>
        </motion.header>
    )
};

export default Header;