import React from 'react';
import {Composition} from 'remotion';
import {DoveNestVision} from './DoveNestVision';

export const Root: React.FC = () => {
  return (
    <Composition
      id="DoveNestVision"
      component={DoveNestVision}
      durationInFrames={240}
      fps={30}
      width={900}
      height={900}
    />
  );
};
